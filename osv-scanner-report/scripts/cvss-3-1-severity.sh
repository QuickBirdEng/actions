usage() {
  echo "Usage: $0 --vector <cvss3.1 vector>"
  exit 1
}

for arg in "$@"; do
  case $arg in
    --vector=*)
      vector="${arg#*=}"
      ;;
    *)
      echo "Unknown argument: $arg"
      usage
      ;;
  esac
done

convert_to_severity() {
    local base_score=$1

    if (( $(echo "$base_score >= 9.0" | bc -l) )); then
        echo "Critical"
    elif (( $(echo "$base_score >= 7.0" | bc -l) )); then
        echo "High"
    elif (( $(echo "$base_score >= 4.0" | bc -l) )); then
        echo "Moderate"
    else
        echo "Low"
    fi
}


AV=$(echo $vector | sed -n 's/.*AV:\([A-Z]*\).*/\1/p') # Attack Vector
AC=$(echo $vector | sed -n 's/.*AC:\([A-Z]*\).*/\1/p') # Attack Complexity
PR=$(echo $vector | sed -n 's/.*PR:\([A-Z]*\).*/\1/p') # Privileges Required
UI=$(echo $vector | sed -n 's/.*UI:\([A-Z]*\).*/\1/p') # User Interaction
C=$(echo $vector | sed -n 's/.*C:\([A-Z]*\).*/\1/p')  # Confidentiality Impact
I=$(echo $vector | sed -n 's/.*I:\([A-Z]*\).*/\1/p')  # Integrity Impact
A=$(echo $vector | sed -n 's/.*A:\([A-Z]*\).*/\1/p')  # Availability Impact
S=$(echo $vector | sed -n 's/.*S:\([A-Z]*\).*/\1/p')  # Scope

case $AV in
    N) AV=0.85 ;;
    A) AV=0.62 ;;
    L) AV=0.55 ;;
    P) AV=0.2 ;;
esac

case $AC in
    H) AC=0.44 ;;
    L) AC=0.77 ;;
esac

if [[ "$S" == "U" ]]; then
    case $PR in
        N) PR=0.85 ;;
        L) PR=0.62 ;;
        H) PR=0.27 ;;
    esac
else
    case $PR in
        N) PR=0.85 ;;
        L) PR=0.68 ;;
        H) PR=0.5 ;;
    esac
fi

case $UI in
    N) UI=0.85 ;;
    R) UI=0.62 ;;
esac

case $C in
    H) C=0.56 ;;
    L) C=0.22 ;;
    N) C=0 ;;
esac

case $I in
    H) I=0.56 ;;
    L) I=0.22 ;;
    N) I=0 ;;
esac

case $A in
    H) A=0.56 ;;
    L) A=0.22 ;;
    N) A=0 ;;
esac

case $S in
    U) S=6.42 ;;
    C) S=7.52 ;;
esac

E=1.0

Exploitability=$(echo "8.22 * $AV * $AC * $PR * $UI" | bc -l)

Impact=$(echo "1 - ((1 - $C) * (1 - $I) * (1 - $A))" | bc -l)
Impact=$(echo "$Impact * $S" | bc -l)

BaseScore=$(bc <<< "if ($Exploitability + $Impact > 10) 10 else $Exploitability + $Impact")
Severity=$(convert_to_severity $BaseScore)

printf "%s (%.1f)" $Severity $BaseScore
