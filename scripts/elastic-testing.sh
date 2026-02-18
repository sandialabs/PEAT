#!/usr/bin/env bash

set -e

SCRIPTDIR="$(dirname "$(readlink -f "$0")")"
COMPOSE_FILE="$SCRIPTDIR/docker-compose.yml"
ES_URL=${ES_URL:-"http://localhost:9200"}  # Default if unset
export ES_VERSION=${2:-"${ES_VERSION:-8.12.1}"}  # Allow version to be specified as argument

check_docker () {
    # Ensure docker is installed before trying to run anything
    if ! command -v 'docker' >/dev/null; then
      echo "docker command not available, is it installed and able to be run by the current user?"
      echo "Installation instructions: https://docs.docker.com/install/linux/docker-ce/ubuntu/#install-docker-engine---community"
      exit 1
    fi
}

stop_containers () {
    check_docker
    docker compose -f "$COMPOSE_FILE" stop
}

remove_containers () {
    check_docker
    docker compose -f "$COMPOSE_FILE" rm --stop --force
}

elastic_only () {
    check_docker
    docker compose -f "$COMPOSE_FILE" up --detach --no-deps elasticsearch
}

run_containers () {
    check_docker
    docker compose -f "$COMPOSE_FILE" up --detach --build
    echo "Elasticsearch is at: http://localhost:9200/"
    echo "Kibana web interface is at: https://localhost:5601/"
    echo "NOTE: it may take several minutes before Kibana is accessible"
    echo "You can check the status with: 'docker logs -f peat-kibana'"
}

check_elastic () {
    curl --proxy "" -f "$ES_URL" >/dev/null 2>/dev/null \
        || { echo "Failed to connect to elastic"; exit 1; }
}

flush_elastic () {
    check_elastic
    FLUSH_INDICES=("ot-device" "peat-logs" "peat-scan-summaries" "peat-pull-summaries" "peat-parse-summaries" "peat-configs" "peat-state")
    for index in "${FLUSH_INDICES[@]}"; do
        curl --proxy "" -XDELETE "$ES_URL/${index}*"
    done
    echo ""
}

# To load data: docker run --rm --network host -v "$(pwd)/elastic_index_export":"/elastic_index_export" --user "$(id -u)":"$(id -g)" --entrypoint multielasticdump elasticdump/elasticsearch-dump:latest --direction=load --input="/elastic_index_export" --output="http://localhost:9200"
export_indices () {
    check_elastic
    DIR_NAME="elastic_index_export"
    CONTAINER_DIR="/tmp/$DIR_NAME"
    ES_EXPORT_DIR=${ES_EXPORT_DIR:-"$(pwd)/$DIR_NAME"}
    INDICES=${EXPORT_INDICES:-"peat-logs peat-scan-summaries peat-pull-summaries peat-parse-summaries peat-configs peat-state ot-device-hosts-static ot-device-hosts-timeseries ot-device-files ot-device-registers ot-device-tags ot-device-io ot-device-events ot-device-memory"}

    echo "Exporting data from Elasticsearch server $ES_URL to $ES_EXPORT_DIR"
    if [ -d "$ES_EXPORT_DIR" ]; then
        echo "Removing data from a previous run..."
        rm -rf "$ES_EXPORT_DIR"/*.json
    else
        mkdir -p "$ES_EXPORT_DIR"
    fi
    chown "$(id -u)":"$(id -g)" "$ES_EXPORT_DIR"
    chmod 775 "$ES_EXPORT_DIR"
    chmod g+s "$ES_EXPORT_DIR"

    # If the index doesn't exist, then elasticdump exits with code 1.
    # "set -e" means the script exits on any non-zero exits, so undo 
    # that until the exports are done
    set +e

    # Use elasticsearch-dump to export Elasticsearch data as JSON files
    # GitHub: https://github.com/elasticsearch-dump/elasticsearch-dump
    # Docker Hub: https://hub.docker.com/r/elasticdump/elasticsearch-dump/
    if command -v multielasticdump >/dev/null; then
        # Dump the indices using the npm-installed command
        echo "Using locally installed elasticsearch-dump ('elasticdump' and 'multielasticdump' commands)"
        for index in ${INDICES}; do
            echo "Exporting all '$index' indices using 'multielasticdump'"
            multielasticdump \
              --quiet \
              --direction=dump \
              --match="^${index}.*$" \
              --input="$ES_URL" \
              --output="$ES_EXPORT_DIR" 1>/dev/null 2>/dev/null
        done
    else
        # Dump the indices using the Docker image
        ESDUMP_IMAGE="elasticdump/elasticsearch-dump:latest"
        echo "'elasticdump' isn't installed, falling back to the Docker image ($ESDUMP_IMAGE)"
        for index in ${INDICES}; do
            echo "Exporting all '$index' indices using 'multielasticdump'"
            docker run \
              --rm \
              --network host \
              -v "$ES_EXPORT_DIR":"$CONTAINER_DIR" \
              --user "$(id -u)":"$(id -g)" \
              --entrypoint multielasticdump \
              "$ESDUMP_IMAGE" \
                --quiet \
                --direction=dump \
                --match="^${index}.*$" \
                --input="$ES_URL" \
                --output="$CONTAINER_DIR"
        done
    fi
    set -e
    echo -e "\nFinished exporting data from Elasticsearch\nExported files are in ${ES_EXPORT_DIR}\n"
}

if [[ "$#" -eq 0 ]]; then
    echo "Usage: elastic-testing.sh {start | stop | cycle | rebuild | cleanup | flush | export | elastic-only} [version] (Default: $ES_VERSION)"
    exit 1
fi

if [[ "$1" = "start" || "$1" = "up" ]]; then
    run_containers
elif [[ "$1" = "elastic" || "$1" = "elastic-only" ]]; then
    elastic_only
elif [[ "$1" = "stop" ]]; then
    stop_containers
elif [[ "$1" = "cycle" ]]; then
    stop_containers
    run_containers
elif [[ "$1" = "rebuild" ]]; then
    remove_containers
    run_containers
elif [[ "$1" = "cleanup" || "$1" = "down" ]]; then
    remove_containers
elif [[ "$1" = "flush" ]]; then
    flush_elastic
elif [[ "$1" = "export" || "$1" = "dump" ]]; then
    export_indices
else
    echo "Invalid argument: $1"
    exit 1
fi
