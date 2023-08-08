#!/usr/bin/env bash

# Function to log errors
log_error() {
  echo "ERROR: $1" >&2
}

# Function to enable GuardDuty in a region
enable_guardduty() {
  local region=$1
  local profile=$2
  local admin_account_id=$3

  delegated_administrator=$(aws-vault exec "$profile" -- aws guardduty list-organization-admin-accounts --region $region | jq -r '.AdminAccounts[].AdminStatus')

  if [ "$delegated_administrator" != "ENABLED" ]; then
    if aws-vault exec "$profile" -- aws guardduty enable-organization-admin-account \
      --admin-account-id "$admin_account_id" --region "$region" 2>> "$ERROR_LOG"; then
      echo "GuardDuty enabled for region $region"
    else
      log_error "Failed to enable GuardDuty for region $region"
    fi
  else
    echo "GuardDuty already enabled in $region"
  fi
}

# Function to enable GuardDuty auto-enable organization members for a region
enable_guardduty_auto_enable() {
  local region=$1
  local profile=$2
  local detector=$3

  org_config=$(aws-vault exec "$profile" -- aws guardduty describe-organization-configuration \
    --detector-id "$detector" --region "$region" | jq -r '.AutoEnable')

  if [ "$org_config" != "true" ]; then
    echo "Starting with $region and detector $detector"
    if aws-vault exec "$profile" -- aws guardduty update-organization-configuration \
      --detector-id "$detector" --auto-enable-organization-members ALL --region "$region" 2>> "$ERROR_LOG"; then
      while read -r account_number email; do
        aws-vault exec "$profile" -- aws guardduty create-members \
          --detector-id "$detector" --account-details "AccountId=$account_number,Email=$email" --region "$region" > /dev/null 2>> "$ERROR_LOG"
      done < <(echo "$accounts_json" | jq -r '.Accounts[] | "\(.Id) \(.Email)"')
      echo "Auto-enabled is now enabled for $region, and member accounts have been added"
    else
      log_error "Failed to auto-enable organization members for detector $detector in region $region"
    fi
  else
    echo "Auto Enable already configured for region $region"
  fi
}

# Main Script
set -e

read -rp "Enter regions governed by Control Tower (separated by spaces): " -a GOVERNED_REGIONS
read -rp "Enter security account ID: " SECURITY_ACCOUNT_ID
read -rp "Enter the aws-vault profile for the management account: " MANAGEMENT_PROFILE
read -rp "Enter the aws-vault profile for the security account: " SECURITY_PROFILE

# Retrieve list of member accounts in Organization
accounts_json=$(aws-vault exec testcontroltower_main -- aws organizations list-accounts)

# Define a log file for error messages
ERROR_LOG="guardduty_errors.log"

# Enable trusted access for GuardDuty from AWS Organizations
if aws-vault exec "$MANAGEMENT_PROFILE" -- aws organizations enable-aws-service-access \
  --service-principal guardduty.amazonaws.com 2>> "$ERROR_LOG"; then
  echo "Trusted access enabled for GuardDuty"
else
  log_error "Failed to enable trusted access, error log is available in $ERROR_LOG"
fi

# Enable GuardDuty in active regions
for region in "${GOVERNED_REGIONS[@]}"; do
  enable_guardduty "$region" "$MANAGEMENT_PROFILE" "$SECURITY_ACCOUNT_ID"
done

# Retrieve detectors for each region
for region in "${GOVERNED_REGIONS[@]}"; do
  detector=$(aws-vault exec "$SECURITY_PROFILE" -- aws guardduty list-detectors --region "$region" | jq -r '.DetectorIds[]' 2>> "$ERROR_LOG")
  enable_guardduty_auto_enable "$region" "$SECURITY_PROFILE" "$detector"
done