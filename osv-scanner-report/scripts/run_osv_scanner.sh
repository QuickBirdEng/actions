#!/bin/bash

calculate_cvss_base_score() {
    local vector=$1
    bash cvss-3-1-severity.sh --vector=$vector
}

reports_dir="osv-scanner-reports"
output_file="$reports_dir/osv-scanner-report.csv"
log_file="$reports_dir/osv-scanner-report.log"

mkdir -p $reports_dir

echo "Library,Type,Current Version,Fixed Version,Severity, Detail" > $output_file

osv-scanner scan -r . | tee -a $log_file

result=$(osv-scanner scan --json -r .)

result=$(echo "$result" | jq -r '.results[].packages[] |
  {
    (.package.name): {
      "version": .package.version,
      "ecosystem": .package.ecosystem,
      "vulnerabilities": (
        .vulnerabilities | map({
          "id": .id,
          "severity_score": (.severity[0].score),
          "fixed_version": (
            .affected[]?.ranges[]?.events[] | select(.fixed) | .fixed // "Not Fixed"
          ),
        })
      )
    }
  }' | jq -s 'add')

keys=$(echo "$result" | jq -r 'keys[]')

for package_name in $keys; do
    package=$(echo "$result" | jq -r ".[\"$package_name\"]")
    echo $package_name
    version=$(echo "$package" | jq -r '.version')
    ecosystem=$(echo "$package" | jq -r '.ecosystem')
    vulnerabilities=$(echo "$package" | jq -r '.vulnerabilities')

    echo "$vulnerabilities" | jq -c '.[]' | while read -r vulnerability; do
       id=$(echo "$vulnerability" | jq -r '.id')
       fixed_version=$(echo "$vulnerability" | jq -r '.fixed_version')
       severity_score=$(echo "$vulnerability" | jq -r '.severity_score')
       severity=$(calculate_cvss_base_score $severity_score)

        echo "$package_name,$ecosystem,$version,$fixed_version,$severity, $id" >> $output_file
    done
done