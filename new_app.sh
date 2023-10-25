#!/bin/bash

POLICY="app"            # default policy is "app"
OUTPUT_FILE="test_policy.json"   # default output file is "test_policy.json"
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PRINT_ONLY=false

# Display a help message
function help() {
  echo
  echo "Create a MinIO policy for an application and add it to your MinIO deployment."
  echo "Help:"
  echo "1) $0 -p admin -n NAME -a ADMIN_IDS [-i|--minio-host MINIO_HOST] [-k|--minio-access-key MINIO_ACCESS_KEY] [-s|--minio-secret-key MINIO_SECRET_KEY] [-c]--oidc-name  [-o OUTPUT_FILE]"
  echo "2) $0 -p app -n NAME -d DEV_IDS -u USER_IDS [-i|--minio-host MINIO_HOST] [-k|--minio-access-key MINIO_ACCESS_KEY] [-s|--minio-secret-key MINIO_SECRET_KEY] [-c]--oidc-name  [-o OUTPUT_FILE]"
  echo "Further info about the arguments:"
  echo "-p, --policy POLICY: Which policy to create. Default is 'app'. "
  echo "-n, --name NAME: the name of the application and policy in MinIO."
  echo "-a --admin-ids ADMIN_IDS: A comma-separated list of group IDs to grant admin access for a admin policy ."
  echo "-d --dev-ids DEV_IDS: A comma-separated list of group IDs to grant access to the application with developer (read/write) access."
  echo "-u --user-ids USER_IDS: A comma-separated list of group IDs to grant access to the application with user (read) access."
  echo "-i, --minio-host MINIO_HOST: the hostname or IP address of your MinIO deployment."
  echo "-k, --minio-access-key MINIO_ACCESS_KEY: the access key for your MinIO deployment."
  echo "-s, --minio-secret-key MINIO_SECRET_KEY: the secret key for your MinIO deployment."
  echo "-c, --oidc-name OIDC_NAME: The identity_openid name to reconfigure on your MinIO deployment."
  echo "-o, --output-file OUTPUT_FILE: the name of the output file. Default is 'test_policy.json'."
  echo "-P, --print-only PRINT_ONLY (true/false): If this flag is set the policy is only written and not added to the MinIO deployment.The defualt is 'false'(optional)"
  echo "-h, --help Show this help message and exit"
  exit 1
}

# Parse command line options
VALID_ARGS=$(getopt -o p:n:g:d:u:a:s:c:o:i:P:h \
--long policy,name:,admin-ids:,developer-ids:,user-ids:,minio-host:,minio-access-key:,minio-secret-key:,oidc-name:,output-file:,print-only:,help -- "$@")
if [[ $? -ne 0 ]]; then
    help
fi


eval set -- "$VALID_ARGS"
while [ : ]; do
  case "$1" in
    -n | --name)
        NAME="$2"
        shift 2
        ;;
    -p | --policy)
        POLICY="$2"
        shift 2
        ;;
    -a | --admin-ids)
        ADMIN_IDS="$2"
        shift 2
        ;;
    -d | --dev-ids)
        DEV_IDS="$2"
        shift 2
        ;;
    -u | --user-ids)
        USER_IDS="$2"
        shift 2
        ;;
    -i | --minio-host)
        MINIO_HOST="$2"
        shift 2
        ;;
    -k | --minio-access-key)
        MINIO_ACCESS_KEY="$2"
        shift 2
        ;;
    -s | --minio-secret-key)
        MINIO_SECRET_KEY="$2"
        shift 2
        ;;
    -c | --oidc-name)
        OIDC_NAME="$2"
        shift 2
        ;;
    -o | --output-file)
        OUTPUT_FILE="$2"
        shift 2
        ;;
    -P | --print-only)
        PRINT_ONLY="$2"
        shift 2
        ;;
    -h | --help)
        help
        shift
        ;;
    --)
      # end of options
      shift
      break
      ;;
    *)
      echo "Unexpected option: $1"
      help
      ;;
  esac
done


# Check that required options are provided
if [[ $POLICY != "admin" && $POLICY != "app" ]]; then
  echo "Invalid policy: $POLICY. Valid values are 'admin' or 'app'." >&2
  exit 1
fi


# Check that the output file is writable
if ! touch "$SCRIPT_DIR/files/$OUTPUT_FILE" &> /dev/null; then
  echo "Error: Output file '$OUTPUT_FILE' is not writable." >&2
  exit 1
fi

if [[ $POLICY == "admin" ]]; then
  NAME="s3admin"
  echo "Creating a admin policy with the name $NAME"
  # Check that admin_ids are provided:
  if [ -z "$ADMIN_IDS" ]; then
    echo "Error: Required to have -a ADMIN_IDS when creating a admin policy."
    exit 1
  fi
  
  # create the MinIO policy using the admin template
  TEMPLATE_FILE="$SCRIPT_DIR/files/template_admin.json"

  # Check that the template file exists
  if [ ! -f "$TEMPLATE_FILE" ]; then
    echo "Error: Template file '$TEMPLATE_FILE' not found."
    exit 1
  fi
  # Construct the policy from the template and add the application name and group IDs

  ADMIN_IDS_Q=$(echo "$ADMIN_IDS" | sed 's/,/","/g' | sed 's/^/"/;s/$/"/')
  POLICY_FILE=$(cat "$TEMPLATE_FILE")
  # loop through each statement in the policy and add the group IDs to the list of authorized JWT groups
  for i in $(echo "$POLICY_FILE" | jq -r '.Statement|keys[]');  do
    POLICY_FILE=$(echo "$POLICY_FILE" | jq ".Statement[$i].Condition = {\"ForAnyValue:StringLike\":{\"jwt:groups\":[$ADMIN_IDS_Q]}}")
  done
fi



if  [[ $POLICY == "app" ]]; then
  # Check that admin_ids are provided:
  if [ -z "$NAME" ]; then
    echo "Error: Required to have a name when creating an policy."
    help
  fi
  # Check that NAME matches bucket naming standard
  if ! [[ "$NAME" =~ ^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$ ]]; then
    echo "Error: NAME does not match MinIO bucket naming standard." >&2
    echo "Bucket names must be between 3 and 63 characters long, start with a lowercase letter or number, and contain only lowercase letters, numbers, and hyphens." >&2
    exit 1
  fi

  # Check that IDS are provided:
  echo "Creating a application policy with the name $NAME"
  if [ -z "$DEV_IDS" ] || [ -z "$USER_IDS" ]; then
    echo "Error: Both -d DEV_IDS and -u USER_IDS are required for creating an application policy."
    exit 1
  fi
  
  # Define variables:
  # Resource path:
  RESOURCE="arn:aws:s3:::${NAME}-*"
  # create the MinIO policy using the app template
  TEMPLATE_FILE="$SCRIPT_DIR/files/template_app.json"
  # Check that the template file exists
  if [ ! -f "$TEMPLATE_FILE" ]; then
    echo "Error: Template file '$TEMPLATE_FILE' not found."
    exit 1
  fi
  # reformatting the lists
  DEV_IDS_Q=$(echo "$DEV_IDS" | sed 's/,/","/g' | sed 's/^/"/;s/$/"/')
  USER_IDS_Q=$(echo "$USER_IDS" | sed 's/,/","/g' | sed 's/^/"/;s/$/"/')
  
  # Construct the policy from the template and add the application name to resources and group id to it corresponding statement
  POLICY_FILE=$(cat "$TEMPLATE_FILE")
  # Add group ids to respected statements
  POLICY_FILE=$(echo "$POLICY_FILE" | jq ".Statement[0].Condition = {\"ForAnyValue:StringLike\":{\"jwt:groups\":[$DEV_IDS_Q]}}")
  POLICY_FILE=$(echo "$POLICY_FILE" | jq ".Statement[1].Condition = {\"ForAnyValue:StringLike\":{\"jwt:groups\":[$USER_IDS_Q]}}")
  # Add resource to respected statements
  POLICY_FILE=$(echo "$POLICY_FILE" | jq ".Statement[0].Resource += [\"$RESOURCE\"]")
  POLICY_FILE=$(echo "$POLICY_FILE" | jq ".Statement[1].Resource += [\"$RESOURCE\"]")
fi

# Write the policy to the output file 
echo "$POLICY_FILE" > "$SCRIPT_DIR/files/$OUTPUT_FILE"
JSON_SIZE=$(wc -c < "$SCRIPT_DIR/files/$OUTPUT_FILE")
echo "AWS IAM policy generated: $OUTPUT_FILE ($JSON_SIZE bytes)"



# Reconfigure the OIDC integration with the new polic and add the policy to the MinIO deployment 
# If you don't want to do this set the -P true
if [ "$PRINT_ONLY" = false ] ; then
  #
  echo "Adding the policy to your MinIO deployment"
  # Load the MinIO secret file
  source $SCRIPT_DIR/minio_secrets.sh
  # Check that MinIO client is installed
  if ! command -v mc &> /dev/null; then
    echo 'Error: MinIO client is not installed or not in PATH.' >&2
    exit 1
  fi

  # Upload the policy file to the MinIO server
  if ! mc alias set minio "https://$MINIO_HOST" "$MINIO_ACCESS_KEY" "$MINIO_SECRET_KEY" --insecure; then
    echo 'Error: Failed to set MinIO alias.' >&2
    exit 1
  fi

  if ! mc admin policy create minio "${NAME}" "$SCRIPT_DIR/files/${OUTPUT_FILE}" --insecure; then
    echo 'Error: Failed to upload policy file to MinIO deployment.' >&2
    exit 1
  fi

 # Get the necessary info from the selected OPENID Configuration
   if [ -z "$OIDC_NAME" ]; then
    echo "Error: Required to have -c OIDC_NAME when reconfiguring the integrated OIDC"
    exit 1
  fi
  
  echo "Extracting info from the selected OIDC ->  identity_openid:$OIDC_NAME"
  OIDC_INFO=$(mc admin config get myminio identity_openid:$OIDC_NAME --insecure)
  CONFIG_URL=$(echo "$OIDC_INFO" | grep -o 'config_url=[^ ]*' | cut -d= -f2)
  REDIRECT_URI=$(echo "$OIDC_INFO" | grep -o 'redirect_uri=[^ ]*' | cut -d= -f2)
  CLIENT_ID=$(echo "$OIDC_INFO" | grep -o 'client_id=[^ ]*' | cut -d= -f2)
  CLIENT_SECRET=$(echo "$OIDC_INFO" | grep -o 'client_secret=[^ ]*' | cut -d= -f2)

  ROLE_POLICY=$(echo "$OIDC_INFO" | grep -o 'role_policy=[^ ]*' | cut -d= -f2)
  
  # Split the input string into an array of strings
  IFS=',' read -ra POLICIES <<< "$ROLE_POLICY"
  # Check if the "new_role" variable is already in the array
  if [[ " ${POLICIES[*]} " == *"${NAME}"* ]]; then
    echo "A ${NAME} policy already exsist in the OIDC configuration."
  else
    # Add the "new_role" variable to the end of the array
    POLICIES+=(${NAME})
    echo "${NAME} was added to the array for the OIDC configuration."
  fi
  # Join the elements of the array into a comma-separated string
  ROLE_POLICY=$(IFS=','; echo "${POLICIES[*]}")
  # reconfigure the OIDC:
  
  if ! mc admin config set minio identity_openid:$OIDC_NAME config_url="$CONFIG_URL" client_id="$CLIENT_ID" client_secret="$CLIENT_SECRET" redirect_uri="$REDIRECT_URI" role_policy="$ROLE_POLICY" --insecure; then
    echo "Error: Failed to reconfigure the identity_openid:$OIDC_NAME" >&2
    exit 1
  fi
 
   if ! mc admin service restart minio --insecure; then
    echo 'Error: Failed to restart MinIO deployment.' >&2
    exit 1
  fi

fi

echo "The $NAME appliation is now ready to use on the MinIO deployment"
