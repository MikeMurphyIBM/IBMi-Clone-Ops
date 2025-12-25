#!/usr/bin/env bash

################################################################################
# JOB 1/2 MERGED: CLONE & PROVISION IBMi LPAR
# Version 3--attaching data volumes as well
# Purpose: Clone volumes from primary LPAR and provision new LPAR with cloned volumes
# Dependencies: IBM Cloud CLI, PowerVS plugin, jq, SSH keys
################################################################################

# ------------------------------------------------------------------------------
# TIMESTAMP LOGGING SETUP
# Prepends timestamp to all output for audit trail
# ------------------------------------------------------------------------------
timestamp() {
    while IFS= read -r line; do
        printf "[%s] %s\n" "$(date '+%Y-%m-%d %H:%M:%S')" "$line"
    done
}
exec > >(timestamp) 2>&1

# ------------------------------------------------------------------------------
# STRICT ERROR HANDLING
# Exit on undefined variables and command failures
# ------------------------------------------------------------------------------
set -eu

################################################################################
# BANNER
################################################################################
echo ""
echo "========================================================================"
echo " JOB 1/2 MERGED v3: CLONE & PROVISION IBMi LPAR"
echo " Purpose: Clone primary LPAR volumes and provision secondary LPAR"
echo "========================================================================"
echo ""

################################################################################
# CONFIGURATION VARIABLES
# Centralized configuration for easy maintenance
################################################################################

# IBM Cloud Authentication
readonly API_KEY="${IBMCLOUD_API_KEY}"
readonly REGION="us-south"
readonly RESOURCE_GROUP="Default"

# PowerVS Workspace Configuration
readonly PVS_CRN="crn:v1:bluemix:public:power-iaas:dal10:a/db1a8b544a184fd7ac339c243684a9b7:973f4d55-9056-4848-8ed0-4592093161d2::"
readonly CLOUD_INSTANCE_ID="973f4d55-9056-4848-8ed0-4592093161d2"
readonly API_VERSION="2024-02-28"

# LPAR Configuration
readonly PRIMARY_LPAR="murphy-prod"
readonly PRIMARY_INSTANCE_ID="fea64706-1929-41c9-a761-68c43a8f29cc"
readonly SECONDARY_LPAR="murphy-prod-clone69"

# Network Configuration
readonly SUBNET_ID="9b9c414e-aa95-41aa-8ed2-40141e0c42fd"
readonly PRIVATE_IP="192.168.10.69"
readonly PUBLIC_SUBNET_NAME="public-net-$(date +"%Y%m%d%H%M%S")"
readonly KEYPAIR_NAME="murph2"

# LPAR Specifications
readonly MEMORY_GB=2
readonly PROCESSORS=0.25
readonly PROC_TYPE="shared"
readonly SYS_TYPE="s1022"
readonly IMAGE_ID="IBMI-EMPTY"
readonly DEPLOYMENT_TYPE="VMNoStorage"

# Naming Convention - Clone YYYY-MM-DD-HH-MM
readonly CLONE_PREFIX="murphy-prod-$(date +"%Y%m%d%H%M")"

# Polling Configuration
readonly POLL_INTERVAL=60
readonly INITIAL_WAIT=45
readonly STATUS_POLL_LIMIT=30
readonly MAX_ATTACH_WAIT=1800
readonly MAX_BOOT_WAIT=1200

# Runtime State Variables
PRIMARY_BOOT_ID=""
PRIMARY_DATA_IDS=""
PRIMARY_VOLUME_IDS=""
TOTAL_VOLUME_COUNT=0
CLONE_TASK_ID=""
CLONE_BOOT_ID=""
CLONE_DATA_IDS=""
PUBLIC_SUBNET_ID=""
IAM_TOKEN=""
SECONDARY_INSTANCE_ID=""
JOB_SUCCESS=0
CURRENT_STEP="INITIALIZATION"

echo "Configuration loaded successfully."
echo ""

################################################################################
# CLEANUP FUNCTION
# Triggered on failure to rollback partially completed operations
################################################################################
cleanup_on_failure() {
    trap - ERR EXIT

    echo "→ cleanup_on_failure triggered (FAILED_STAGE=${FAILED_STAGE:-UNKNOWN})"

    # If job succeeded, do nothing
    if [[ ${JOB_SUCCESS:-0} -eq 1 ]]; then
        return 0
    fi

    FAILED_AT="${FAILED_STAGE:-UNKNOWN_STAGE}"

    echo ""
    echo "========================================================================"
    echo " JOB FAILED — PRESERVING RECOVERY ARTIFACTS"
    echo "========================================================================"
    echo ""
    echo "Failure detected at stage: ${FAILED_AT}"
    echo ""

    # Only detach and mark volumes for relevant failures
    case "$FAILED_AT" in
        ATTACH_VOLUME|BOOT_CONFIG|STARTUP|FINAL_STATUS_CHECK)
            CLEANUP_VOLUMES=1
            ;;
        *)
            CLEANUP_VOLUMES=0
            ;;
    esac

    if [[ "$CLEANUP_VOLUMES" -ne 1 ]]; then
        echo "Failure stage does not require volume cleanup — skipping"
        return 0
    fi

    # Detach any attached volumes
    if [[ -n "$SECONDARY_INSTANCE_ID" && -n "$CLONE_BOOT_ID" ]]; then
        echo "→ Attempting to detach volumes from secondary LPAR..."
        
        set +e
        ibmcloud pi instance volume detach-all "$SECONDARY_INSTANCE_ID" >/dev/null 2>&1
        set -e
        
        echo "  Volume detachment initiated"
        sleep 30
    fi

    # Mark boot volume as FAILED
    if [[ -n "$CLONE_BOOT_ID" ]]; then
        echo "→ Marking boot volume as FAILED..."

        CURRENT_NAME=$(ibmcloud pi volume get "$CLONE_BOOT_ID" --json \
            | jq -r '.name')

        if [[ "$CURRENT_NAME" != *"__FAILED" ]]; then
            ibmcloud pi volume update "$CLONE_BOOT_ID" \
                --name "${CURRENT_NAME}__FAILED" \
                >/dev/null 2>&1 || true
        fi

        echo "  Boot volume preserved: ${CURRENT_NAME}__FAILED"
    fi

    # Mark data volumes as FAILED (even if not attached)
    if [[ -n "$CLONE_DATA_IDS" ]]; then
        for VOL in ${CLONE_DATA_IDS//,/ }; do
            echo "→ Marking data volume ${VOL} as FAILED..."

            CURRENT_NAME=$(ibmcloud pi volume get "$VOL" --json \
                | jq -r '.name')

            if [[ "$CURRENT_NAME" != *"__FAILED" ]]; then
                ibmcloud pi volume update "$VOL" \
                    --name "${CURRENT_NAME}__FAILED" \
                    >/dev/null 2>&1 || true
            fi

            echo "  Data volume preserved: ${CURRENT_NAME}__FAILED"
        done
    fi

    echo ""
    echo "========================================================================"
    echo " FAILURE SUMMARY"
    echo "========================================================================"
    echo " Secondary LPAR : ${SECONDARY_LPAR}"
    echo " Failure stage  : ${FAILED_AT}"
    echo " Volumes marked : __FAILED"
    echo " Empty LPAR     : Preserved (can be reused)"
    echo " Cleanup job    : Run Job 3 to clean up failed volumes"
    echo "========================================================================"
    echo ""
}

################################################################################
# HELPER FUNCTION: WAIT FOR ASYNC CLONE JOB
################################################################################
wait_for_clone_job() {
    local task_id=$1
    echo "→ Waiting for asynchronous clone task: ${task_id}..."
    
    while true; do
        STATUS=$(ibmcloud pi volume clone-async get "$task_id" --json \
            | jq -r '.status')
        
        if [[ "$STATUS" == "completed" ]]; then
            echo "✓ Clone task completed successfully"
            break
        elif [[ "$STATUS" == "failed" ]]; then
            echo "✗ ERROR: Clone task failed"
            FAILED_STAGE="CLONE_OPERATION"
            exit 1
        else
            echo "  Clone task status: ${STATUS} - waiting ${POLL_INTERVAL}s..."
            sleep "$POLL_INTERVAL"
        fi
    done
}

################################################################################
# ACTIVATE CLEANUP TRAP
################################################################################
trap 'cleanup_on_failure' ERR EXIT

################################################################################
# STAGE I: IBM CLOUD AUTHENTICATION & WORKSPACE TARGETING
################################################################################
CURRENT_STEP="IBM_CLOUD_LOGIN"

echo "========================================================================"
echo " STAGE I: IBM CLOUD AUTHENTICATION & WORKSPACE TARGETING"
echo "========================================================================"
echo ""

echo "→ Authenticating to IBM Cloud (Region: ${REGION})..."
ibmcloud login --apikey "$API_KEY" -r "$REGION" > /dev/null 2>&1 || {
    echo "✗ ERROR: IBM Cloud login failed"
    FAILED_STAGE="AUTHENTICATION"
    exit 1
}
echo "✓ Authentication successful"

echo "→ Targeting resource group: ${RESOURCE_GROUP}..."
ibmcloud target -g "$RESOURCE_GROUP" > /dev/null 2>&1 || {
    echo "✗ ERROR: Failed to target resource group"
    FAILED_STAGE="AUTHENTICATION"
    exit 1
}
echo "✓ Resource group targeted"

echo "→ Targeting PowerVS workspace..."
ibmcloud pi ws target "$PVS_CRN" > /dev/null 2>&1 || {
    echo "✗ ERROR: Failed to target PowerVS workspace"
    FAILED_STAGE="AUTHENTICATION"
    exit 1
}
echo "✓ PowerVS workspace targeted"

echo ""
echo "------------------------------------------------------------------------"
echo " Stage I Complete: Authentication successful"
echo "------------------------------------------------------------------------"
echo ""

################################################################################
# STAGE II: IDENTIFY VOLUMES ON PRIMARY LPAR
################################################################################
CURRENT_STEP="IDENTIFY_VOLUMES"

echo "========================================================================"
echo " STAGE II: IDENTIFY VOLUMES ON PRIMARY LPAR"
echo "========================================================================"
echo ""

echo "→ Querying volumes on primary LPAR: ${PRIMARY_LPAR}..."

PRIMARY_VOLUME_DATA=$(ibmcloud pi ins vol ls "$PRIMARY_INSTANCE_ID" --json 2>/dev/null)

echo "→ Identifying boot and data volumes..."

# Extract boot volume ID
PRIMARY_BOOT_ID=$(echo "$PRIMARY_VOLUME_DATA" | jq -r '
    .volumes[]? | select(.bootVolume == true) | .volumeID
' | head -n 1)

# Extract data volume IDs
set +e
PRIMARY_DATA_IDS=$(echo "$PRIMARY_VOLUME_DATA" | jq -r '
    .volumes[]? | select(.bootVolume != true) | .volumeID
' 2>/dev/null | paste -sd "," - 2>/dev/null)
set -e

# Clean up empty result
if [[ -z "$PRIMARY_DATA_IDS" || "$PRIMARY_DATA_IDS" == "" ]]; then
    PRIMARY_DATA_IDS=""
fi

if [[ -z "$PRIMARY_BOOT_ID" ]]; then
    echo "✗ ERROR: No boot volume found on primary LPAR"
    FAILED_STAGE="IDENTIFY_VOLUMES"
    exit 1
fi

# Build complete volume ID list for cloning
if [[ -n "$PRIMARY_DATA_IDS" ]]; then
    PRIMARY_VOLUME_IDS="${PRIMARY_BOOT_ID},${PRIMARY_DATA_IDS}"
else
    PRIMARY_VOLUME_IDS="${PRIMARY_BOOT_ID}"
fi

# Count total volumes
IFS=',' read -ra _VOLS <<<"$PRIMARY_VOLUME_IDS"
TOTAL_VOLUME_COUNT=${#_VOLS[@]}
unset _VOLS

echo "✓ Volumes identified on primary LPAR"
echo "  Boot volume:  ${PRIMARY_BOOT_ID}"
echo "  Data volumes: ${PRIMARY_DATA_IDS:-None}"
echo "  Total volumes to clone: ${TOTAL_VOLUME_COUNT}"

echo ""
echo "------------------------------------------------------------------------"
echo " Stage II Complete: Volume identification complete"
echo "------------------------------------------------------------------------"
echo ""

################################################################################
# STAGE III: SSH TO IBMi AND RUN PREPARATION COMMANDS
################################################################################
CURRENT_STEP="IBMI_PREPARATION"

echo "========================================================================"
echo " STAGE III: IBMi PREPARATION"
echo "========================================================================"
echo ""

echo "→ Installing SSH keys from Code Engine secrets..."

mkdir -p "$HOME/.ssh"
chmod 700 "$HOME/.ssh"

# VSI SSH Key (RSA)
VSI_KEY_FILE="$HOME/.ssh/id_rsa"
if [ -z "${id_rsa:-}" ]; then
  echo "✗ ERROR: id_rsa environment variable is not set"
  FAILED_STAGE="SSH_SETUP"
  exit 1
fi
echo "$id_rsa" > "$VSI_KEY_FILE"
chmod 600 "$VSI_KEY_FILE"
echo "  ✓ VSI SSH key installed"

# IBMi SSH Key (ED25519)
IBMI_KEY_FILE="$HOME/.ssh/id_ed25519_vsi"
if [ -z "${id_ed25519_vsi:-}" ]; then
  echo "✗ ERROR: id_ed25519_vsi environment variable is not set"
  FAILED_STAGE="SSH_SETUP"
  exit 1
fi
echo "$id_ed25519_vsi" > "$IBMI_KEY_FILE"
chmod 600 "$IBMI_KEY_FILE"
echo "  ✓ IBMi SSH key installed"
echo ""

echo "→ Connecting to IBMi via VSI for disk preparation..."

ssh -i "$VSI_KEY_FILE" \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  murphy@52.118.255.179 \
  "ssh -i /home/murphy/.ssh/id_ed25519_vsi \
       -o StrictHostKeyChecking=no \
       -o UserKnownHostsFile=/dev/null \
       murphy@192.168.0.109 \
       'system \"CHGTCPIFC INTNETADR('\''192.168.0.109'\'') AUTOSTART(*NO)\"; \
        sleep 5; \
        system \"CALL PGM(QSYS/QAENGCHG) PARM(*ENABLECI)\"; \
        sleep 5; \
        system \"CHGASPACT ASPDEV(*SYSBAS) OPTION(*FRCWRT)\"; \
        sleep 30; \
        system \"CHGASPACT ASPDEV(*SYSBAS) OPTION(*SUSPEND) SSPTIMO(120)\"'" || true

echo "  ✓ IBMi preparation commands completed - ASP suspended for 120 seconds"
echo ""

echo "------------------------------------------------------------------------"
echo " Stage III Complete: IBMi preparation successful"
echo "------------------------------------------------------------------------"
echo ""

################################################################################
# STAGE IV: PERFORM CLONE-ASYNC OPERATION
################################################################################
CURRENT_STEP="CLONE_ASYNC"

echo "========================================================================"
echo " STAGE IV: VOLUME CLONE OPERATION"
echo "========================================================================"
echo ""

echo "→ Waiting 15 seconds before initiating volume clone..."
sleep 15
echo ""

echo "→ Submitting clone request..."
echo "  Clone prefix: ${CLONE_PREFIX}"
echo "  Source volumes: ${PRIMARY_VOLUME_IDS}"

CLONE_JSON=$(ibmcloud pi volume clone-async create "$CLONE_PREFIX" \
        --volumes "$PRIMARY_VOLUME_IDS" \
        --json) || {
        echo "✗ ERROR: Clone request failed"
        FAILED_STAGE="CLONE_OPERATION"
        exit 1
}

CLONE_TASK_ID=$(echo "$CLONE_JSON" | jq -r '.cloneTaskID')

if [[ -z "$CLONE_TASK_ID" || "$CLONE_TASK_ID" == "null" ]]; then
    echo "✗ ERROR: cloneTaskID not returned"
    echo "$CLONE_JSON"
    FAILED_STAGE="CLONE_OPERATION"
    exit 1
fi

echo "✓ Clone request submitted successfully"
echo "  Clone task ID: ${CLONE_TASK_ID}"
echo ""

echo "------------------------------------------------------------------------"
echo " Stage IV Complete: Clone operation initiated"
echo "------------------------------------------------------------------------"
echo ""

################################################################################
# STAGE V: CREATE PUBLIC SUBNET
################################################################################
CURRENT_STEP="CREATE_PUBLIC_SUBNET"

echo "========================================================================"
echo " STAGE V: PUBLIC SUBNET CREATION"
echo "========================================================================"
echo ""

echo "→ Creating public subnet: ${PUBLIC_SUBNET_NAME}..."

PUBLIC_SUBNET_JSON=$(ibmcloud pi subnet create "$PUBLIC_SUBNET_NAME" \
    --net-type public \
    --json 2>/dev/null)

PUBLIC_SUBNET_ID=$(echo "$PUBLIC_SUBNET_JSON" | jq -r '.id // .networkID // empty' 2>/dev/null || true)

if [[ -z "$PUBLIC_SUBNET_ID" || "$PUBLIC_SUBNET_ID" == "null" ]]; then
    echo "✗ ERROR: Failed to create public subnet"
    echo "Response: $PUBLIC_SUBNET_JSON"
    FAILED_STAGE="CREATE_PUBLIC_SUBNET"
    exit 1
fi

echo "✓ Public subnet created successfully"
echo "  Name: ${PUBLIC_SUBNET_NAME}"
echo "  ID:   ${PUBLIC_SUBNET_ID}"
echo ""

echo "------------------------------------------------------------------------"
echo " Stage V Complete: Public subnet ready"
echo "------------------------------------------------------------------------"
echo ""

################################################################################
# STAGE VI: EMPTY IBMi LPAR CREATION AND DEPLOYMENT
################################################################################
CURRENT_STEP="CREATE_LPAR"

echo "========================================================================"
echo " STAGE VI: EMPTY IBMi LPAR CREATION & DEPLOYMENT"
echo "========================================================================"
echo ""

echo "→ Retrieving IAM access token for API authentication..."

IAM_RESPONSE=$(curl -s -X POST "https://iam.cloud.ibm.com/identity/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -H "Accept: application/json" \
    -d "grant_type=urn:ibm:params:oauth:grant-type:apikey" \
    -d "apikey=${API_KEY}")

IAM_TOKEN=$(echo "$IAM_RESPONSE" | jq -r '.access_token // empty' 2>/dev/null || true)

if [[ -z "$IAM_TOKEN" || "$IAM_TOKEN" == "null" ]]; then
    echo "✗ ERROR: IAM token retrieval failed"
    echo "Response: $IAM_RESPONSE"
    FAILED_STAGE="IAM_TOKEN"
    exit 1
fi

export IAM_TOKEN
echo "✓ IAM token retrieved successfully"
echo ""

echo "→ Building LPAR configuration payload..."

# Construct JSON payload for LPAR creation
PAYLOAD=$(cat <<EOF
{
  "serverName": "${SECONDARY_LPAR}",
  "processors": ${PROCESSORS},
  "memory": ${MEMORY_GB},
  "procType": "${PROC_TYPE}",
  "sysType": "${SYS_TYPE}",
  "imageID": "${IMAGE_ID}",
  "deploymentType": "${DEPLOYMENT_TYPE}",
  "keyPairName": "${KEYPAIR_NAME}",
  "networks": [
    {
      "networkID": "${SUBNET_ID}",
      "ipAddress": "${PRIVATE_IP}"
    },
    {
      "networkID": "${PUBLIC_SUBNET_ID}"
    }
  ]
}
EOF
)

echo "  Network Configuration:"
echo "    - Private: ${SUBNET_ID} (IP: ${PRIVATE_IP})"
echo "    - Public:  ${PUBLIC_SUBNET_ID} (${PUBLIC_SUBNET_NAME})"
echo ""

API_URL="https://${REGION}.power-iaas.cloud.ibm.com/pcloud/v1/cloud-instances/${CLOUD_INSTANCE_ID}/pvm-instances?version=${API_VERSION}"

echo "→ Submitting LPAR creation request to PowerVS API..."

# Retry logic for API resilience
ATTEMPTS=0
MAX_ATTEMPTS=3

while [[ $ATTEMPTS -lt $MAX_ATTEMPTS && -z "$SECONDARY_INSTANCE_ID" ]]; do
    ATTEMPTS=$((ATTEMPTS + 1))
    echo "  Attempt ${ATTEMPTS}/${MAX_ATTEMPTS}..."
    
    set +e
    RESPONSE=$(curl -s -X POST "${API_URL}" \
        -H "Authorization: Bearer ${IAM_TOKEN}" \
        -H "CRN: ${PVS_CRN}" \
        -H "Content-Type: application/json" \
        -d "${PAYLOAD}" 2>&1)
    CURL_CODE=$?
    set -e
    
    if [[ $CURL_CODE -ne 0 ]]; then
        echo "  ⚠ WARNING: curl failed with exit code ${CURL_CODE}"
        sleep 5
        continue
    fi
    
    # Safe jq parsing - handles multiple response formats
    SECONDARY_INSTANCE_ID=$(echo "$RESPONSE" | jq -r '
        .pvmInstanceID? //
        (.[0].pvmInstanceID? // empty) //
        .pvmInstance.pvmInstanceID? //
        empty
    ' 2>/dev/null || true)
    
    if [[ -z "$SECONDARY_INSTANCE_ID" || "$SECONDARY_INSTANCE_ID" == "null" ]]; then
        echo "  ⚠ WARNING: Could not extract instance ID - retrying..."
        sleep 5
    fi
done

if [[ -z "$SECONDARY_INSTANCE_ID" || "$SECONDARY_INSTANCE_ID" == "null" ]]; then
    echo "✗ FAILURE: Could not retrieve LPAR instance ID after ${MAX_ATTEMPTS} attempts"
    echo ""
    echo "API Response:"
    echo "$RESPONSE"
    FAILED_STAGE="CREATE_LPAR"
    exit 1
fi

echo "✓ LPAR creation request accepted"
echo ""
echo "  LPAR Details:"
echo "  ┌────────────────────────────────────────────────────────────"
echo "  │ Name:        ${SECONDARY_LPAR}"
echo "  │ Instance ID: ${SECONDARY_INSTANCE_ID}"
echo "  │ Private IP:  ${PRIVATE_IP}"
echo "  │ Private Net: ${SUBNET_ID}"
echo "  │ Public Net:  ${PUBLIC_SUBNET_ID} (${PUBLIC_SUBNET_NAME})"
echo "  │ CPU Cores:   ${PROCESSORS}"
echo "  │ Memory:      ${MEMORY_GB} GB"
echo "  │ Proc Type:   ${PROC_TYPE}"
echo "  │ System Type: ${SYS_TYPE}"
echo "  └────────────────────────────────────────────────────────────"
echo ""

echo "------------------------------------------------------------------------"
echo " Stage VI Complete: LPAR creation initiated"
echo "------------------------------------------------------------------------"
echo ""

################################################################################
# STAGE VII: PROVISIONING WAIT & STATUS POLLING
################################################################################
CURRENT_STEP="LPAR_PROVISIONING"

echo "========================================================================"
echo " STAGE VII: LPAR PROVISIONING & STATUS POLLING"
echo "========================================================================"
echo ""

echo "→ Waiting ${INITIAL_WAIT} seconds for initial provisioning..."
sleep $INITIAL_WAIT
echo ""

echo "→ Beginning status polling (interval: ${POLL_INTERVAL}s, max attempts: ${STATUS_POLL_LIMIT})..."
echo ""

STATUS=""
ATTEMPT=1

while true; do
    set +e
    STATUS_JSON=$(ibmcloud pi ins get "$SECONDARY_INSTANCE_ID" --json 2>/dev/null)
    STATUS_EXIT=$?
    set -e
    
    if [[ $STATUS_EXIT -ne 0 ]]; then
        echo "  ⚠ WARNING: Status retrieval failed - retrying..."
        sleep "$POLL_INTERVAL"
        continue
    fi
    
    STATUS=$(echo "$STATUS_JSON" | jq -r '.status // empty' 2>/dev/null || true)
    echo "  Status Check (${ATTEMPT}/${STATUS_POLL_LIMIT}): ${STATUS}"
    
    # Success condition: LPAR is in final stopped state
    if [[ "$STATUS" == "SHUTOFF" || "$STATUS" == "STOPPED" ]]; then
        echo ""
        echo "✓ LPAR reached SHUTOFF state: ${STATUS}"
        break
    fi
    
    # Timeout condition
    if (( ATTEMPT >= STATUS_POLL_LIMIT )); then
        echo ""
        echo "✗ FAILURE: Status polling timed out after ${STATUS_POLL_LIMIT} attempts"
        FAILED_STAGE="LPAR_PROVISIONING"
        exit 1
    fi
    
    ((ATTEMPT++))
    sleep "$POLL_INTERVAL"
done

echo ""
echo "------------------------------------------------------------------------"
echo " Stage VII Complete: LPAR provisioned and in SHUTOFF state"
echo "------------------------------------------------------------------------"
echo ""

################################################################################
# STAGE VIII: CHECK CLONE COMPLETION & IDENTIFY BOOT VOLUME
################################################################################
CURRENT_STEP="CLONE_COMPLETION"

echo "========================================================================"
echo " STAGE VIII: CLONE COMPLETION & VOLUME IDENTIFICATION"
echo "========================================================================"
echo ""

# Wait for clone job to complete
wait_for_clone_job "$CLONE_TASK_ID"

echo ""
echo "→ Extracting cloned volume IDs..."

CLONE_RESULT=$(ibmcloud pi volume clone-async get "$CLONE_TASK_ID" --json)

# Extract boot volume clone
CLONE_BOOT_ID=$(echo "$CLONE_RESULT" \
  | jq -r --arg boot "$PRIMARY_BOOT_ID" '
      .clonedVolumes[]
      | select(.sourceVolumeID == $boot)
      | .clonedVolumeID
  ')

# Extract data volume clones (if any)
if [[ -n "$PRIMARY_DATA_IDS" ]]; then
  CLONE_DATA_IDS=$(echo "$CLONE_RESULT" \
    | jq -r --arg boot "$PRIMARY_BOOT_ID" '
        .clonedVolumes[]
        | select(.sourceVolumeID != $boot)
        | .clonedVolumeID
    ' | paste -sd "," -)
fi

# Validation
if [[ -z "$CLONE_BOOT_ID" ]]; then
  echo "✗ ERROR: Failed to identify cloned boot volume"
  echo "$CLONE_RESULT"
  FAILED_STAGE="CLONE_COMPLETION"
  exit 1
fi

echo "✓ Cloned volume IDs extracted"
echo "  Boot volume: ${CLONE_BOOT_ID}"
echo "  Data volumes: ${CLONE_DATA_IDS:-None}"
echo ""

echo "→ Verifying cloned volumes are available..."

# Verify boot volume
while true; do
    BOOT_STATUS=$(ibmcloud pi volume get "$CLONE_BOOT_ID" --json \
        | jq -r '.state | ascii_downcase')
    
    if [[ "$BOOT_STATUS" == "available" ]]; then
        echo "✓ Boot volume available: ${CLONE_BOOT_ID}"
        break
    fi
    
    echo "  Boot volume status: ${BOOT_STATUS} - waiting..."
    sleep "$POLL_INTERVAL"
done

# Verify data volumes (if any)
if [[ -n "$CLONE_DATA_IDS" ]]; then
    for VOL in ${CLONE_DATA_IDS//,/ }; do
        while true; do
            DATA_STATUS=$(ibmcloud pi volume get "$VOL" --json \
                | jq -r '.state | ascii_downcase')
            
            if [[ "$DATA_STATUS" == "available" ]]; then
                echo "✓ Data volume available: ${VOL}"
                break
            fi
            
            echo "  Data volume status: ${DATA_STATUS} - waiting..."
            sleep "$POLL_INTERVAL"
        done
    done
fi

echo ""
echo "------------------------------------------------------------------------"
echo " Stage VIII Complete: All volumes cloned and available"
echo "------------------------------------------------------------------------"
echo ""

################################################################################
# STAGE IX: ATTACH BOOT VOLUME (DATA VOLUMES COMMENTED OUT)
################################################################################
CURRENT_STEP="ATTACH_VOLUME"

echo "========================================================================"
echo " STAGE IX: ATTACH BOOT VOLUME TO SECONDARY LPAR"
echo "========================================================================"
echo ""

echo "→ Attaching boot volume to secondary LPAR..."
echo "  LPAR: ${SECONDARY_LPAR}"
echo "  Instance ID: ${SECONDARY_INSTANCE_ID}"
echo "  Boot Volume ID: ${CLONE_BOOT_ID}"
echo ""

# --- Attach boot volume as regular volume ---
echo "→ Attaching boot volume (as regular volume)..."

set +e
ibmcloud pi instance volume attach "$SECONDARY_INSTANCE_ID" \
    --volumes "$CLONE_BOOT_ID"
ATTACH_RC=$?
set -e

echo ""

if [[ $ATTACH_RC -ne 0 ]]; then
    echo "✗ ERROR: Boot volume attachment failed (exit code: $ATTACH_RC)"
    FAILED_STAGE="ATTACH_VOLUME"
    exit 1
fi

echo "✓ Boot volume attachment request accepted"
echo ""

# --- Wait for boot volume to be visible ---
echo "→ Waiting for boot volume to be confirmed attached..."

BOOT_ELAPSED=0
BOOT_CONFIRMED=false

while [[ $BOOT_ELAPSED -lt $MAX_ATTACH_WAIT ]]; do
    VOL_LIST=$(ibmcloud pi instance volume list "$SECONDARY_INSTANCE_ID" --json 2>/dev/null \
        | jq -r '(.volumes // [])[]?.volumeID')

    if grep -qx "$CLONE_BOOT_ID" <<<"$VOL_LIST"; then
        echo "✓ Boot volume confirmed attached: ${CLONE_BOOT_ID}"
        BOOT_CONFIRMED=true
        break
    fi

    echo "  Boot volume not visible yet - checking again in ${POLL_INTERVAL}s..."
    sleep "$POLL_INTERVAL"
    BOOT_ELAPSED=$((BOOT_ELAPSED + POLL_INTERVAL))
done

if [[ "$BOOT_CONFIRMED" == "false" ]]; then
    FAILED_STAGE="ATTACH_VOLUME"
    echo "✗ ERROR: Boot volume not attached after ${MAX_ATTACH_WAIT}s"
    exit 1
fi

echo ""

# --- Mark volume as bootable ---
echo "→ Marking volume as bootable..."
echo "  Volume ID: ${CLONE_BOOT_ID}"
echo ""

set +e
ibmcloud pi volume update "$CLONE_BOOT_ID" --bootable >/dev/null 2>&1
UPDATE_RC=$?
set -e

echo ""

if [[ $UPDATE_RC -ne 0 ]]; then
    echo "✗ ERROR: Failed to mark volume as bootable (exit code: $UPDATE_RC)"
    FAILED_STAGE="ATTACH_VOLUME"
    exit 1
fi

echo "✓ Volume marked as bootable"
echo ""

### DATA VOLUME ATTACHMENT - COMMENTED OUT FOR TESTING ###
#: <<'DATA_VOLUME_ATTACH'
# --- Attach data volumes individually (if any) ---
if [[ -n "$CLONE_DATA_IDS" ]]; then
    echo "→ Attaching data volumes individually..."
    
    # Convert comma-separated IDs to array
    IFS=',' read -ra DATA_VOL_ARRAY <<<"$CLONE_DATA_IDS"
    DATA_VOL_COUNT=${#DATA_VOL_ARRAY[@]}
    
    echo "  Total data volumes to attach: ${DATA_VOL_COUNT}"
    echo ""
    
    VOL_NUM=1
    for DATA_VOL_ID in "${DATA_VOL_ARRAY[@]}"; do
        echo "→ Attaching data volume ${VOL_NUM}/${DATA_VOL_COUNT}..."
        echo "  Volume ID: ${DATA_VOL_ID}"
        echo ""
        
        set +e
        ibmcloud pi instance volume attach "$SECONDARY_INSTANCE_ID" \
            --volumes "$DATA_VOL_ID"
        ATTACH_RC=$?
        set -e
        
        echo ""
        
        if [[ $ATTACH_RC -ne 0 ]]; then
            echo "✗ ERROR: Data volume attachment failed (exit code: $ATTACH_RC): ${DATA_VOL_ID}"
            FAILED_STAGE="ATTACH_VOLUME"
            exit 1
        fi
        
        echo "✓ Data volume attachment request accepted"
        echo ""
        
        # Wait for this data volume to be confirmed
        echo "→ Waiting for data volume to be confirmed attached..."
        
        DATA_ELAPSED=0
        DATA_CONFIRMED=false
        
        while [[ $DATA_ELAPSED -lt $MAX_ATTACH_WAIT ]]; do
            VOL_LIST=$(ibmcloud pi instance volume list "$SECONDARY_INSTANCE_ID" --json 2>/dev/null \
                | jq -r '(.volumes // [])[]?.volumeID')
            
            if grep -qx "$DATA_VOL_ID" <<<"$VOL_LIST"; then
                echo "✓ Data volume confirmed attached: ${DATA_VOL_ID}"
                DATA_CONFIRMED=true
                break
            fi
            
            echo "  Data volume not visible yet - checking again in ${POLL_INTERVAL}s..."
            sleep "$POLL_INTERVAL"
            DATA_ELAPSED=$((DATA_ELAPSED + POLL_INTERVAL))
        done
        
        if [[ "$DATA_CONFIRMED" == "false" ]]; then
            FAILED_STAGE="ATTACH_VOLUME"
            echo "✗ ERROR: Data volume not attached after ${MAX_ATTACH_WAIT}s: ${DATA_VOL_ID}"
            exit 1
        fi
        
        echo ""
        ((VOL_NUM++))
    done
    
    echo "✓ All data volumes attached successfully"
else
    echo "→ No data volumes to attach - boot volume only"
fi

echo ""
echo "→ Pausing 300 seconds to allow system stabilization..."
sleep 300
echo ""
#DATA_VOLUME_ATTACH

echo "------------------------------------------------------------------------"
echo " Stage IX Complete: Boot volume attached and marked as bootable"
echo "------------------------------------------------------------------------"
echo ""
echo "Pausing for 5 minutes to ensure volumes are attached and ready for operations"
sleep 300

################################################################################
# STAGE X: CONFIGURE BOOT MODE
################################################################################
CURRENT_STEP="BOOT_CONFIG"

echo "========================================================================"
echo " STAGE X: CONFIGURE BOOT MODE"
echo "========================================================================"
echo ""

echo "→ Configuring boot mode (NORMAL, Disk B)..."

BOOTCFG_SUCCESS=0

for BOOTCFG_ATTEMPT in 1 2; do
    echo "  Boot config attempt ${BOOTCFG_ATTEMPT}/2"

    set +e
    BOOTCFG_OUTPUT=$(ibmcloud pi instance operation "$SECONDARY_INSTANCE_ID" \
        --operation-type boot \
        --boot-mode b \
        --boot-operating-mode normal 2>&1)
    RC=$?
    set -e

    echo "$BOOTCFG_OUTPUT"

    if [[ $RC -eq 0 ]]; then
        echo "✓ Boot mode configured"
        BOOTCFG_SUCCESS=1
        break
    fi

    sleep 60
done

if [[ $BOOTCFG_SUCCESS -ne 1 ]]; then
    FAILED_STAGE="BOOT_CONFIG"
    exit 1
fi

echo ""
echo "------------------------------------------------------------------------"
echo " Stage X Complete: Boot mode configured"
echo "------------------------------------------------------------------------"
echo ""

################################################################################
# STAGE XI: START LPAR
################################################################################
CURRENT_STEP="STARTUP"

echo "========================================================================"
echo " STAGE XI: START SECONDARY LPAR"
echo "========================================================================"
echo ""

sleep 60
echo "→ Starting LPAR..."

START_SUCCESS=0

for START_ATTEMPT in 1 2 3; do
    echo "  Start attempt ${START_ATTEMPT}/3"

    set +e
    START_OUTPUT=$(ibmcloud pi instance action "$SECONDARY_INSTANCE_ID" \
        --operation start 2>&1)
    RC=$?
    set -e

    echo "$START_OUTPUT"

    if [[ $RC -eq 0 ]]; then
        echo "✓ Start command accepted"
        START_SUCCESS=1
        break
    fi

    # Retryable failure handling
    if echo "$START_OUTPUT" | grep -q "attaching_volume"; then
        echo "⚠ Instance still attaching volumes — retrying"
    else
        echo "✗ Non-retryable start failure"
        FAILED_STAGE="STARTUP"
        exit 1
    fi

    sleep 60
done

if [[ $START_SUCCESS -ne 1 ]]; then
    FAILED_STAGE="STARTUP"
    exit 1
fi

echo ""
echo "------------------------------------------------------------------------"
echo " Stage XI Complete: LPAR start initiated"
echo "------------------------------------------------------------------------"
echo ""

################################################################################
# STAGE XII: WAIT FOR LPAR TO REACH ACTIVE STATE
################################################################################
CURRENT_STEP="WAIT_FOR_ACTIVE"

echo "========================================================================"
echo " STAGE XII: WAIT FOR LPAR TO REACH ACTIVE STATE"
echo "========================================================================"
echo ""

echo "→ Waiting for LPAR to reach ACTIVE state..."
echo ""

BOOT_ELAPSED=0

while [[ $BOOT_ELAPSED -lt $MAX_BOOT_WAIT ]]; do
    set +e
    STATUS=$(ibmcloud pi instance get "$SECONDARY_INSTANCE_ID" --json 2>/dev/null \
        | jq -r '.status // "UNKNOWN"')
    set -e

    echo "  LPAR status: ${STATUS} (elapsed ${BOOT_ELAPSED}s)"

    if [[ "$STATUS" == "ACTIVE" ]]; then
        echo "✓ LPAR is ACTIVE"
        break
    fi

    if [[ "$STATUS" == "ERROR" ]]; then
        FAILED_STAGE="STARTUP"
        exit 1
    fi

    sleep "$POLL_INTERVAL"
    BOOT_ELAPSED=$((BOOT_ELAPSED + POLL_INTERVAL))
done

if [[ "$STATUS" != "ACTIVE" ]]; then
    FAILED_STAGE="STARTUP"
    exit 1
fi

echo ""
echo "------------------------------------------------------------------------"
echo " Stage XII Complete: LPAR is ACTIVE"
echo "------------------------------------------------------------------------"
echo ""

################################################################################
# STAGE XIII: FINAL IBMi COMMANDS (SSH BACK TO IBMi)
################################################################################
CURRENT_STEP="FINAL_IBMI_COMMANDS"

echo "========================================================================"
echo " STAGE XIII: FINAL IBMi CONFIGURATION"
echo "========================================================================"
echo ""

echo "→ Connecting to IBMi to re-enable primary INTNETADR for autostart and flush to disk..."

ssh -i "$VSI_KEY_FILE" \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  murphy@52.118.255.179 \
  "ssh -i /home/murphy/.ssh/id_ed25519_vsi \
       -o StrictHostKeyChecking=no \
       -o UserKnownHostsFile=/dev/null \
       murphy@192.168.0.109 \
       'system \"CHGTCPIFC INTNETADR('\''192.168.0.109'\'') AUTOSTART(*YES)\"; \
        system \"CHGASPACT ASPDEV(*SYSBAS) OPTION(*FRCWRT)\"'" || true

echo "  ✓ TCP/IP autostart enabled and ASP flushed to disk"
echo ""

echo "------------------------------------------------------------------------"
echo " Stage XIII Complete: Final IBMi configuration complete"
echo "------------------------------------------------------------------------"
echo ""

################################################################################
# FINAL VALIDATION & SUMMARY
################################################################################

echo ""
echo "========================================================================"
echo " JOB 1/2 MERGED: COMPLETION SUMMARY"
echo "========================================================================"
echo ""

# --- Safely retrieve final status ---
set +e
INSTANCE_JSON=$(ibmcloud pi instance get "$SECONDARY_INSTANCE_ID" --json 2>/dev/null)
RC=$?
set -e

if [[ $RC -ne 0 || -z "$INSTANCE_JSON" ]]; then
    echo "✗ ERROR: Unable to retrieve final LPAR status"
    FAILED_STAGE="FINAL_STATUS_CHECK"
    exit 1
fi

FINAL_STATUS=$(echo "$INSTANCE_JSON" | jq -r '.status // "UNKNOWN"')

echo "→ Final LPAR status check: ${FINAL_STATUS}"
echo ""

# --- FAILURE PATH ---
if [[ "$FINAL_STATUS" != "ACTIVE" ]]; then
    echo ""
    echo "========================================================================"
    echo " FINAL STATE CHECK FAILED"
    echo "========================================================================"
    echo ""
    echo "✗ Secondary LPAR did not remain ACTIVE"
    echo "  Final status: ${FINAL_STATUS}"
    echo ""

    FAILED_STAGE="FINAL_STATUS_CHECK"
    exit 1
fi

# ===========================
# SUCCESS PATH
# ===========================

echo "========================================================================"
echo " JOB COMPLETED SUCCESSFULLY"
echo "========================================================================"
echo ""
echo "  Status:                  ✓ SUCCESS"
echo "  Primary LPAR:            ${PRIMARY_LPAR}"
echo "  Secondary LPAR:          ${SECONDARY_LPAR}"
echo "  Secondary Instance ID:   ${SECONDARY_INSTANCE_ID}"
echo "  Final Status:            ${FINAL_STATUS}"
echo "  ────────────────────────────────────────────────────────────────"
echo "  Volumes Cloned:          ✓ Yes"
echo ""
echo "  Boot Volume:"
echo "    - ${CLONE_BOOT_ID}"
echo ""

echo "  Data Volumes:"
if [[ -n "$CLONE_DATA_IDS" ]]; then
    IFS=',' read -ra _DATA_VOLS <<<"$CLONE_DATA_IDS"
    for VOL in "${_DATA_VOLS[@]}"; do
        echo "    - ${VOL}"
    done
else
    echo "    - None"
fi
unset _DATA_VOLS

echo ""
echo "  Volumes Attached:        ✓ Boot volume only (data volumes commented out)"
echo "  Boot Mode:               ✓ NORMAL (Mode B)"
echo "  ────────────────────────────────────────────────────────────────"
echo "  Clone Prefix:            ${CLONE_PREFIX}"
echo "  Public Subnet:           ${PUBLIC_SUBNET_ID} (${PUBLIC_SUBNET_NAME})"
echo ""
echo "  Next Steps:"
echo "  - Secondary LPAR is ${FINAL_STATUS} and ready for backup operations"
echo "  - Data volumes are cloned but not attached (commented out)"
echo "  - To attach data volumes, uncomment Stage IX data volume section"
echo ""
echo "========================================================================"
echo ""

# --- Mark success FIRST ---
JOB_SUCCESS=1

# --- Disable cleanup trap ONLY AFTER success ---
trap - ERR EXIT

echo ""
echo "========================================================================"
echo ""

# Give logs time to flush before exit
sleep 2

exit 0
