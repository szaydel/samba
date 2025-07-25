#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

tfile="${CTDB_TEST_TMP_DIR}/tunable.$$"
tfile2="${CTDB_TEST_TMP_DIR}/tunable2.$$"
tdir="${CTDB_TEST_TMP_DIR}/tunabled.$$"

remove_files()
{
	rm -f "$tfile" "$tfile2"
	rm -f "${tdir}/"* 2>/dev/null || true
	rmdir "$tdir" 2>/dev/null || true
}
test_cleanup remove_files

defaults="\
SeqnumInterval=1000
ControlTimeout=60
TraverseTimeout=20
KeepaliveInterval=5
KeepaliveLimit=5
RecoverTimeout=30
RecoverInterval=1
ElectionTimeout=3
TakeoverTimeout=9
MonitorInterval=15
TickleUpdateInterval=20
EventScriptTimeout=30
MonitorTimeoutCount=20
RecoveryGracePeriod=120
RecoveryBanPeriod=300
DatabaseHashSize=100001
DatabaseMaxDead=5
RerecoveryTimeout=10
EnableBans=1
NoIPFailback=0
VerboseMemoryNames=0
RecdPingTimeout=60
RecdFailCount=10
LogLatencyMs=0
RecLockLatencyMs=1000
RecoveryDropAllIPs=120
VacuumInterval=10
VacuumMaxRunTime=120
RepackLimit=10000
VacuumFastPathCount=60
MaxQueueDropMsg=1000000
AllowUnhealthyDBRead=0
StatHistoryInterval=1
DeferredAttachTO=120
AllowClientDBAttach=1
FetchCollapse=1
HopcountMakeSticky=50
StickyDuration=600
StickyPindown=200
NoIPTakeover=0
DBRecordCountWarn=100000
DBRecordSizeWarn=10000000
DBSizeWarn=100000000
PullDBPreallocation=10485760
LockProcessesPerDB=200
RecBufferSizeLimit=1000000
QueueBufferSize=1024
IPAllocAlgorithm=2
AllowMixedVersions=0
"

ok_tunable_defaults()
{
	ok "$defaults"
}

tunable_log()
{
	_level="$1"
	_msg="$2"

	_all=":DEBUG:INFO:NOTICE:WARNING:ERR:"
	# Keep the debug levels log at.  This strips off the levels up
	# to and including the current $CTDB_DEBUGLEVEL, but then puts
	# back $CTDB_DEBUGLEVEL.  Cheaper than a loop...
	_want=":${CTDB_DEBUGLEVEL}:${_all#*":${CTDB_DEBUGLEVEL}:"}"

	case "$_want" in
	*":${_level}:"*)
		log="${log}${_msg}
" # Intentional newline
		;;
	esac
}

# Update $_map with tunable settings from 1 file
# values
ok_tunable_1()
{
	_file="$1"

	if [ ! -r "$_file" ]; then
		tunable_log "INFO" "Optional tunables file ${_file} not found"
		return
	fi

	tunable_log "NOTICE" "Loading tunables from ${_file}"

	while IFS='= 	' read -r _var _val; do
		case "$_var" in
		\#* | "") continue ;;
		esac
		_decval=$((_val))
		_vl=$(echo "$_var" | tr '[:upper:]' '[:lower:]')
		_map=$(echo "$_map" |
			sed -e "s|^\\(${_vl}:.*=\\).*\$|\\1${_decval}|")
	done <"$_file"
}

# Set required output to a version of $defaults where values for
# tunables specified in the given file(s) replace the default values
ok_tunable()
{
	_f1="${1:-"${tfile}"}"
	_f2="${2:-""}"

	# Construct a version of $defaults prepended with a lowercase
	# version of the tunable variable, to allow case-insensitive
	# matching.  This would be easier with the GNU sed
	# case-insensitivity flag, but that is less portable.  The $0
	# condition in awk causes empty lines to be skipped, in case
	# there are trailing empty lines in $defaults.
	_map=$(echo "$defaults" |
		awk -F= '$0 { printf "%s:%s=%s\n", tolower($1), $1, $2 }')

	log=""

	#
	# Replace values for tunables that are set in each file
	#

	ok_tunable_1 "$_f1"

	if [ -n "$_f2" ]; then
		if [ -f "$_f2" ]; then
			ok_tunable_1 "$_f2"
		elif [ -d "$_f2" ]; then
			for _t in "${_f2}/"*.tunables; do
				if [ ! -e "$_t" ]; then
					break
				fi
				ok_tunable_1 "$_t"
			done
		elif [ ! -e "$_f2" ]; then
			tunable_log "INFO" "Optional tunables directory ${_f2} not found"
		fi
	fi

	# Set result, stripping off lowercase tunable prefix
	ok "${log}$(echo "$_map" | awk -F: '{ print $2 }')"
}

export CTDB_DEBUGLEVEL="INFO"

test_case "Unreadable file"
: >"$tfile"
chmod a-r "$tfile"
uid=$(id -u)
# root can read unreadable files
if [ "$uid" = 0 ]; then
	ok_tunable_defaults
else
	required_error EINVAL <<EOF
ctdb_tunable_load_file: Failed to open ${tfile}
EOF
fi
unit_test tunable_test "$tfile"
rm -f "$tfile"

test_case "Invalid file, contains 1 word"
echo "Hello" >"$tfile"
required_error EINVAL <<EOF
Loading tunables from ${tfile}
${tfile}: Invalid tunables line containing "Hello"
EOF
unit_test tunable_test "$tfile"

test_case "Invalid file, contains multiple words"
echo "Hello world!" >"$tfile"
required_error EINVAL <<EOF
Loading tunables from ${tfile}
${tfile}: Invalid tunables line containing "Hello world!"
EOF
unit_test tunable_test "$tfile"

test_case "Invalid file, missing value"
echo "EnableBans=" >"$tfile"
required_error EINVAL <<EOF
Loading tunables from ${tfile}
${tfile}: Invalid tunables line containing "EnableBans"
EOF
unit_test tunable_test "$tfile"

test_case "Invalid file, invalid value (not a number)"
echo "EnableBans=value" >"$tfile"
required_error EINVAL <<EOF
Loading tunables from ${tfile}
${tfile}: Invalid value "value" for tunable "EnableBans"
EOF
unit_test tunable_test "$tfile"

test_case "Invalid file, missing key"
echo "=123" >"$tfile"
required_error EINVAL <<EOF
Loading tunables from ${tfile}
${tfile}: Syntax error
EOF
unit_test tunable_test "$tfile"

test_case "Invalid file, missing key but space before ="
cat >"$tfile" <<EOF
 =0
EOF
required_error EINVAL <<EOF
Loading tunables from ${tfile}
${tfile}: Syntax error
EOF
unit_test tunable_test "$tfile"

test_case "Invalid file, unknown tunable"
echo "HelloWorld=123" >"$tfile"
required_error EINVAL <<EOF
Loading tunables from ${tfile}
${tfile}: Unknown tunable "HelloWorld"
EOF
unit_test tunable_test "$tfile"

test_case "Invalid file, obsolete tunable"
echo "MaxRedirectCount=123" >"$tfile"
required_error EINVAL <<EOF
Loading tunables from ${tfile}
${tfile}: Obsolete tunable "MaxRedirectCount"
EOF
unit_test tunable_test "$tfile"

test_case "Invalid file, trailing non-whitespace garbage"
echo "EnableBans=0xgg" >"$tfile"
required_error EINVAL <<EOF
Loading tunables from ${tfile}
${tfile}: Invalid value "0xgg" for tunable "EnableBans"
EOF
unit_test tunable_test "$tfile"

test_case "Invalid file, multiple errors"
cat >"$tfile" <<EOF
EnableBans=
EnableBans=value
=123
HelloWorld=123
MaxRedirectCount =123
EOF
required_error EINVAL <<EOF
Loading tunables from ${tfile}
${tfile}: Invalid tunables line containing "EnableBans"
${tfile}: Invalid value "value" for tunable "EnableBans"
${tfile}: Syntax error
EOF
unit_test tunable_test "$tfile"

test_case "Invalid file, errors followed by valid"
cat >"$tfile" <<EOF
HelloWorld=123
EnableBans=value
EnableBans=0
EOF
required_error EINVAL <<EOF
Loading tunables from ${tfile}
${tfile}: Unknown tunable "HelloWorld"
${tfile}: Invalid value "value" for tunable "EnableBans"
EOF
unit_test tunable_test "$tfile"

test_case "OK, missing file"
rm -f "$tfile"
ok_tunable
unit_test tunable_test "$tfile"

test_case "OK, empty file"
: >"$tfile"
ok_tunable
unit_test tunable_test "$tfile"

test_case "OK, comments and blanks only"
cat >"$tfile" <<EOF
# This is a comment

# There are also some blank lines


EOF
ok_tunable
unit_test tunable_test "$tfile"

test_case "OK, 1 tunable"
cat >"$tfile" <<EOF
EnableBans=0
EOF
ok_tunable
unit_test tunable_test "$tfile"

test_case "OK, 1 tunable, hex"
cat >"$tfile" <<EOF
EnableBans=0xf
EOF
ok_tunable
unit_test tunable_test "$tfile"

test_case "OK, 1 tunable, octal"
cat >"$tfile" <<EOF
EnableBans=072
EOF
ok_tunable
unit_test tunable_test "$tfile"

test_case "OK, 1 tunable, tab before ="
cat >"$tfile" <<EOF
EnableBans	=0
EOF
ok_tunable
unit_test tunable_test "$tfile"

test_case "OK, 1 tunable, space after ="
cat >"$tfile" <<EOF
EnableBans= 0
EOF
ok_tunable
unit_test tunable_test "$tfile"

test_case "OK, 2 tunables, multiple spaces around ="
cat >"$tfile" <<EOF
EnableBans      =  0
RecoverInterval = 10
EOF
ok_tunable
unit_test tunable_test "$tfile"

test_case "OK, 2 tunables, whitespace everywhere"
cat >"$tfile" <<EOF
	EnableBans      = 0  
	RecoverInterval = 10 
EOF
ok_tunable
unit_test tunable_test "$tfile"

test_case "OK, several tunables"
cat >"$tfile" <<EOF
EnableBans=0
RecoverInterval=10
ElectionTimeout=5
EOF
ok_tunable
unit_test tunable_test "$tfile"

test_case "OK, several tunables, varying case"
cat >"$tfile" <<EOF
enablebans=0
ReCoVerInTeRvAl=10
ELECTIONTIMEOUT=5
EOF
ok_tunable
unit_test tunable_test "$tfile"

test_case "OK, miscellaneous..."
cat >"$tfile" <<EOF
# Leading comment
enablebans=0
ReCoVerInTeRvAl	 =    10

# Intermediate comment after a blank line
  ELECTIONTIMEOUT=25   


# Final comment among blanks lines




EOF
ok_tunable
unit_test tunable_test "$tfile"

#
# Subsequent tests will use the same 1st file, to reduce clutter
#

cat >"$tfile" <<EOF
EnableBans=0
RecoverInterval=10
ElectionTimeout=5
EOF

#
# 2nd argument is a file
#

test_case "OK, several tunables, empty 2nd file"
: >"$tfile2"
ok_tunable "$tfile" "$tfile2"
unit_test tunable_test "$tfile" "$tfile2"

test_case "OK, several tunables, 2nd file disjoint"
cat >"$tfile2" <<EOF
RecoverTimeout=123
EOF
ok_tunable "$tfile" "$tfile2"
unit_test tunable_test "$tfile" "$tfile2"

test_case "OK, several tunables, 2nd file overlaps"
cat >"$tfile2" <<EOF
RecoverTimeout=123
ElectionTimeout=10
EOF
ok_tunable "$tfile" "$tfile2"
unit_test tunable_test "$tfile" "$tfile2"

#
# 2nd argument is a directory
#

test_case "OK, several tunables, missing directory"
rm -f "$tfile2"
rmdir "$tdir" 2>/dev/null || true
ok_tunable "$tfile" "$tdir"
unit_test tunable_test "$tfile" "$tdir"

test_case "OK, several tunables, empty directory"
mkdir -p "$tdir"
ok_tunable "$tfile" "$tdir"
unit_test tunable_test "$tfile" "$tdir"

test_case "OK, several tunables, README in directory"
cat >"${tdir}/README" <<EOF
This will be ignored because the file doesn't end in ".tunables"

RecoverInterval=55
EOF
ok_tunable "$tfile" "$tdir"
unit_test tunable_test "$tfile" "$tdir"

#
# README can stay there...
#
# Subsequent testcases add files, leaving existing ones there
#

test_case "OK, several tunables,  single file in directory"
cat >"${tdir}/f70.tunables" <<EOF
RecoverInterval=45
EOF
ok_tunable "$tfile" "$tdir"
unit_test tunable_test "$tfile" "$tdir"

test_case "OK, several tunables,  2 disjoint files in directory"
cat >"${tdir}/f10.tunables" <<EOF
RecoverTimeout=42
EOF
ok_tunable "$tfile" "$tdir"
unit_test tunable_test "$tfile" "$tdir"

test_case "OK, several tunables,  3rd file in directory overlaps"
cat >"${tdir}/f40.tunables" <<EOF
RecoverInterval=21
RecoverTimeout=54
EOF
ok_tunable "$tfile" "$tdir"
unit_test tunable_test "$tfile" "$tdir"

test_case "OK, several tunables, error in directory file"
cat >"${tdir}/f20.tunables" <<EOF
Oops!
EOF
required_error EINVAL <<EOF
Loading tunables from ${tfile}
Loading tunables from ${tdir}/f10.tunables
Loading tunables from ${tdir}/f20.tunables
${tdir}/f20.tunables: Invalid tunables line containing "Oops!"
Loading tunables from ${tdir}/f40.tunables
Loading tunables from ${tdir}/f70.tunables
EOF
unit_test tunable_test "$tfile" "$tdir"
