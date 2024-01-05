all_targets="$(cargo metadata --no-deps --format-version=1 | jq --raw-output '.packages.[].metadata."docs.rs".targets | join(" ")')"
