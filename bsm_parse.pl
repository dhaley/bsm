#!/usr/bin/perl -w

use strict;
use Getopt::Long;

#################################################################################
#                                                                               #
# Copyright 2008 EDS, Inc. All Rights Reserved.                                 #
#                                                                               #  
# $Id: bsm_parse.pl,v 1.6 2008/11/17 20:35:34 dh196264 Exp dh196264 $           #
#                                                                               #
#################################################################################


#
#        audit event ID (AUE_EXECVE, etc...), hostname (because the record
#        could be from a ZONE), 
#        time in epoch, COUNT (# times cmd/arg
#        repeated), command, arguments, 
#        auditid (role that typed command), real
#        id (of process. In process header, if any)


#################################################################
# Set up command line option stuff                              #
#################################################################
my ($help,$verbose,$debug,$test_file,$show_progress,$output_file);
# GLOBAL VARIABLES
if (! GetOptions ( 
"test_file=s" => \$test_file,
"show_progress" => \$show_progress,
"output_file=s" => \$output_file,
"debug" => \$debug,
"verbose" => \$verbose,
"help" => \$help )
   ) { die "Incorrect options passed!\n" }

if (defined $help ) {
    usage()
}



#die "We need more power! (this program must be run as root)" if $>; 
# praudit -l -d$'\t' /var/audit/20081110092001.20081111092001.n1gsps-bc-s4
my $praudit_command = "/usr/sbin/praudit -d'\t' -l";
my $auditreduce_command = '/usr/sbin/auditreduce';
my $tracking_file = '/etc/security/audit_last_timestamp';

# MAIN
# see if there is a bsm_parse_track file, which contains last timestamp processed
if (! -f $tracking_file) {
    if (defined $verbose) {
	print "Trakcing file doens't exist: Creating $tracking_file\n";
    }
}
else {
    open TIMESTAMP, $tracking_file or die "can't open $tracking_file: $!";
    my $timestamp = (<TIMESTAMP>);
    chomp $timestamp;
    if (defined $verbose) {
	print "Using [$tracking_file] last timestamp of $timestamp\n";
    }
    close TIMESTAMP;
}

if (defined $verbose) { 
		print "Using Output File: $output_file\n";
}


my ($PRAUDIT_RECORDS);
if (defined $test_file ) {
	my $audit_file = $test_file;
	unless ( -f $audit_file ) {
		die "$audit_file is not a valid file: $!";
	}
	if (defined $verbose) { 
		print "Using Test File: $audit_file\n";
	}
	$PRAUDIT_RECORDS = readTestFile($audit_file);
}
else {
    my $ZIP_LOGS;
    $ZIP_LOGS = unzipLogs(); # upzip logs if necessary
    $PRAUDIT_RECORDS = readAuditFiles();
    if (defined $ZIP_LOGS) {
	if ( scalar @{$ZIP_LOGS} > 1 ) {
	    zipLogs($ZIP_LOGS); # Only zip files that were zipped previously
	}
    }
}

my $AUDIT_EVENT_IDS;
my $BSM_RECORD_OBJECT = AuditReport->new();	# Create new Report Object
my $BSM_OBJECTS = createBSMObjects($PRAUDIT_RECORDS, $BSM_RECORD_OBJECT);

printSummaryReports($BSM_OBJECTS);

if (defined $AUDIT_EVENT_IDS) {
    if ( scalar(@{$AUDIT_EVENT_IDS}) > 1) {
	print "\n\n\n";
	foreach my $event_id (sort @{$AUDIT_EVENT_IDS} ) {
	    print "|| (\$AUDIT_EVENT_ID eq '$event_id') ";
	}
    }
}



###############################################################################################
# Subroutines

#########################################################################################
# usage statement                                                                       #
#########################################################################################
sub usage {
print "Usage: $0 [options]...\n";
print "Run BSM Record Summary Report\n";
#print "(This script must be run as root)\n";
print "\n";
print "  --test_file           will use $test_file instead of praudit output\n";
print "  --show_progress       turn on progress bars in manual mode (don't use from cron) NIS\n";
print "  --output_file         file_name to write reports to\n";
print "  --verbose             turn on verbosity \n";
print "  --debug               turn on print debug statements \n";
print "  --help                show this usage statement and exit \n";
print "                           \n";
exit;
}

sub unzipLogs {
    my $audit_dir = '/var/audit';
    my ($COMPRESSED_FILES,$audit_log);
    my $gunzip = '/usr/bin/gunzip';
    unless (-f $gunzip) {
	$gunzip = '/usr/dist/exe/gunzip';
    }
    my $arg = '-f';
    opendir (AUDIT_DIR, $audit_dir) or die "can't opendir $audit_dir: $!";
    while (defined($audit_log = readdir(AUDIT_DIR) ) ) {
	next if $audit_log =~ /^\.\.?$/; # skip . and ..
	if ($audit_log =~ /^\d{14}\.\S{14}\.[^\.]+\.gz$/ ) { # is gzipped
	    my $full_file = "$audit_dir/$audit_log";
	    print "Unzipping $full_file\n";
	    my $status = system($gunzip, $arg, $full_file);
	    if ($status == 0) {
		substr($audit_log, -3) = "";   #remove the ".gz" from log file
		push @{$COMPRESSED_FILES}, "$audit_dir/$audit_log";
	    }
	    else {
		warn "$gunzip exited funny: $?" unless $status == 0;
	    }
	}
    }
    return $COMPRESSED_FILES;
}

sub zipLogs {
    my $COMPRESSED_FILES = shift;
    my $gzip = "/usr/bin/gzip";
    unless (-f $gzip) {
	$gzip = '/usr/dist/exe/gzip';
    }
    foreach my $audit_log ( @{$COMPRESSED_FILES} ) {
	print "Zipping $audit_log\n";
	my $status = system($gzip, $audit_log);
	warn "$gzip exited funny: $?" unless $status == 0;
    }
}

# Get output of Audit File
sub readAuditFiles {
    # An absolute date-time takes the form:
    # yyyymmdd [ hh [ mm [ ss ]]]
    # An offset can be specified as: +n d|h|m| s where n is  a
    # number  of  units, and the tags d, h, m, and s stand for
    # days,  hours,  minutes  and  seconds,  respectively.  An
    # offset is relative to the starting time. Thus, this form
    # can only be used with the -b option.
    my $command = "$auditreduce_command | $praudit_command";
	my $OUTPUT;
	if (defined $verbose) {
	    print "Running $command\n";
	}
	my $pid = open(PRAUDIT, "$command |") or die "Couldn't fork: $!";
	while (<PRAUDIT>) {
		my $line = $_;
		chomp $line;
		push @{$OUTPUT}, $line;
	}
	close PRAUDIT;
	return $OUTPUT;
}

# Get output of Test File
sub readTestFile {
	my $audit_file = shift;
	my $OUTPUT;
	open PRAUDIT, $audit_file or die "Couldn't fork: $!";
	while (<PRAUDIT>) {
		my $line = $_;
		chomp $line;
		push @{$OUTPUT}, $line;
	}
	close PRAUDIT;
	return $OUTPUT;
}

# Objectify lines from PRAUDIT output
sub createBSMObjects {
    my $PRAUDIT_RECORDS = shift; # array of BSM record lines

    if ( (defined $PRAUDIT_RECORDS) && ( scalar(@{$PRAUDIT_RECORDS}) > 1 ) ) {
	my $audit_record_count = @{$PRAUDIT_RECORDS};
	if ($verbose) {
	    print "There are [$audit_record_count] records\n";
	}
    }
    else {
	die "PRAUDIT_RECORDS were not generated\n";
    }

    my $BAD_AUDIT_EVENT_ID;
    my $first_line = shift @{$PRAUDIT_RECORDS};
    my $last_line = pop @{$PRAUDIT_RECORDS};
    unless ( $first_line =~ /^file/ ) {
	print "$first_line\n";
	die "first line $first_line did not begin with file";
    }
    unless ( $last_line =~ /^file/ ) {
	print "$last_line\n";
	die "last line $last_line did not end with file";
    }
    my $PROCESS_IDS;    # Need a data structure to store PIDs.....
    my $PARENT_PROCESS_IDS;
    RECORD: foreach my $audit_record ( @{$PRAUDIT_RECORDS} ) {
	my @TOKENS = split /\t/, $audit_record;
	my $A_RECORD = AuditRecord->new();	# Create new Audit Object
	$A_RECORD->audit_Init(@TOKENS);
	my $label = $A_RECORD->getLabel;
	###################################################################################################
 	if ($label eq 'header' ) { # *header token *
	    my $AUDIT_EVENT_ID = $A_RECORD->parseHeader; # process header
	    my $secs = $A_RECORD->{'secs'};
	    ##############################################################################################
 	    if ($AUDIT_EVENT_ID eq 'execve(2)' ) { # *execve(2) token*
		$label = $A_RECORD->getLabel;
		if ($label eq 'path') {
		    $A_RECORD->parsePath; # "attribute
		    my $absolute_path =  $A_RECORD->{'absolute_path'};
		    $label = $A_RECORD->getLabel;
		    #########################################################################################
		    if ($label eq 'attribute') { # The *attribute token*
			$A_RECORD->parseAttribute;
			$label = $A_RECORD->getLabel;
			###################################################################################
			if ($label eq 'exec_args') { # *exec_args* token
			    $A_RECORD->parseExecArgs();
			    $label = $A_RECORD->getLabel;
			    if ($label eq 'subject') {
				my ($process_id,$effective_user_id,$real_user_id,$machine_id,$audit_session_id) 
				    = $A_RECORD->parseSubject;
				$label = $A_RECORD->getLabel;
				if ($label eq 'return') {
				    my $error_status = $A_RECORD->parseReturn();
				    unless (  $error_status eq 'success') {
					next RECORD;
				    }
				}
				$label = $A_RECORD->getLabel;
				my $zone;
				if ($label eq 'zone') {
				    $zone = $A_RECORD->parseZone;
				}
				unless ( $A_RECORD->getTokenNum() == 0 ) {
				    die "Tokens have not all been processed";
				}
				my $pfexec_debug_string;
				if ($absolute_path eq '/usr/bin/pfexec') {
				    # let's record that we were here
				    ${$PROCESS_IDS}{$process_id} = 1; # only want to skip future pids if pfexec
				    $pfexec_debug_string = "$absolute_path\n";			    
				    foreach my $arg ( @{$A_RECORD->{'EXEC_ARGS'}} ) {
					$pfexec_debug_string .= "\t$arg\n";
				    }
				    $pfexec_debug_string .= "\n\n";
				    my $pfexec = shift @{$A_RECORD->{'EXEC_ARGS'}}; # grab first argument

				    if ( scalar(@{$A_RECORD->{'EXEC_ARGS'}}) > 0 ) {
					$absolute_path = shift @{$A_RECORD->{'EXEC_ARGS'}}; # works most of the time
					if ($absolute_path eq '/usr/bin/pfexec') {
					    $absolute_path = shift @{$A_RECORD->{'EXEC_ARGS'}};
					}
				    }
				}

				if ($absolute_path eq '/usr/bin/sbin/sh') {
				    shift @{$A_RECORD->{'EXEC_ARGS'}} if ${$A_RECORD->{'EXEC_ARGS'}}[0] eq 'sh';
				    shift @{$A_RECORD->{'EXEC_ARGS'}} if ${$A_RECORD->{'EXEC_ARGS'}}[0] eq '-c';
				    shift @{$A_RECORD->{'EXEC_ARGS'}} if ${$A_RECORD->{'EXEC_ARGS'}}[0] eq '/bin/sh';
				    shift @{$A_RECORD->{'EXEC_ARGS'}} if ${$A_RECORD->{'EXEC_ARGS'}}[0] eq '/usr/bin/pfexec';
				    my $full_path = shift @{$A_RECORD->{'EXEC_ARGS'}};
				    my @ARGS = split /[ ]/, $full_path;
				    $absolute_path = shift @ARGS;
				    $A_RECORD->setArgs(@ARGS);
				}
				if ($absolute_path eq '/usr/bin/pfexec') {
				    $absolute_path = shift @{$A_RECORD->{'EXEC_ARGS'}}; # works most of the time
				    if ($absolute_path eq '/usr/bin/pfexec') {
					$absolute_path = shift @{$A_RECORD->{'EXEC_ARGS'}};
				    }
#				    print "$absolute_path $real_user_id $effective_user_id\n";
				    foreach my $arg ( @{$A_RECORD->{'EXEC_ARGS'}} ) {
#					print "\t$arg\n"
				    }
				}
				if (exists ${$PROCESS_IDS}{$process_id} ) {
				    next RECORD;
				}
				elsif (exists ${$PARENT_PROCESS_IDS}{$audit_session_id} ) {
				    next RECORD;
				    if (defined $verbose) {
					print "PROCESS: Process ID: $process_id exists \n";
					print "$process_id,$effective_user_id,$real_user_id,$machine_id\n";
					print "PARENT_PROCESS_IDS matched\n";
					$A_RECORD->printTokens;
				    }
				}
				else {
				    if (defined $verbose) {
					if (defined $pfexec_debug_string) {
					    print "$pfexec_debug_string";
					}
				    }
				}

				if ( $machine_id =~ /0.0.0.0/ ) {
 				    next RECORD;
				    if (defined $verbose) {
					print "0.0.0.0 matched\n";
					print "PROCESS: Process ID: $process_id exists \n";
					print "$process_id,$effective_user_id,$real_user_id,$machine_id\n";
					$A_RECORD->printTokens;
					print "\n\n\n";
				    }
				}

				$BSM_RECORD_OBJECT->createGoodCommands($absolute_path,$secs,$real_user_id,$effective_user_id);
				my $arg_string = $A_RECORD->getArgString;
				if (defined $arg_string) {
				    $BSM_RECORD_OBJECT->createGoodCommandArgs($absolute_path,$secs,$real_user_id,$effective_user_id,$arg_string);
				}
			    }
			    else {
				unless ($label =~ /^failure/ ) {
				    if (defined $verbose) {
					print "ONE: $label\n";
					$A_RECORD->printTokens;
				    }
				}
			    }
			}
			elsif ($label eq 'subject') { # these are only for *failure* s
			    my ($process_id,$effective_user_id,$real_user_id,$machine_id,$audit_session_id) 
				= $A_RECORD->parseSubject;
			    if ( ($effective_user_id eq 'metricnp') || ($real_user_id eq 'metricnp') ) {
				if (defined $verbose) {
				    print "A\n";
				    print "$process_id,$effective_user_id,$real_user_id,$machine_id,$audit_session_id\n";
				    $A_RECORD->printTokens;
				}
			    }
			    $label = $A_RECORD->getLabel;
			    my $error_status = $A_RECORD->parseReturn();
			    if (  $error_status eq 'success') {
				if (defined $verbose) {
				    print "TWO: $label\n";
				    $A_RECORD->printTokens;
				}
			    }
			    $label = $A_RECORD->getLabel;
			    my $zone;
			    if ($label eq 'zone') {
				$zone = $A_RECORD->parseZone;
			    }
			    $label = $A_RECORD->getLabel;
			    if (defined $label) {
				unless ($label =~ /^failure/ ) {
				    if (defined $verbose) {
					print "TWO: $label\n";
					$A_RECORD->printTokens;
				    }
				}
			    }
			}
			else {
			    unless ($label =~ /^failure/ ) {
				if (defined $verbose) {
				    print "THREE: $label\n";
				    $A_RECORD->printTokens;
				}
			    }
			}
		    }
		    elsif ($label eq 'subject') { # *subject token* We don't care, it's just *failure* s
			my ($process_id,$effective_user_id,$real_user_id,$machine_id,$audit_session_id) 
			    = $A_RECORD->parseSubject;
			if ( ($effective_user_id eq 'metricnp') || ($real_user_id eq 'metricnp') ) {
			    if (defined $verbose) {
				print "B\n";
				print "$process_id,$effective_user_id,$real_user_id,$machine_id,$audit_session_id\n";
				$A_RECORD->printTokens;
			    }
			}

			$label = $A_RECORD->getLabel;
			if ($label eq 'return') {
			    my $error_status = $A_RECORD->parseReturn();
			    if (  $error_status eq 'success') {
				if (defined $verbose) {
				    print "FOUR: $label\n";
				    $A_RECORD->printTokens;
				}
			    }
			}
			my $zone;
			$label = $A_RECORD->getLabel;
			if ($label eq 'zone') {
			    $zone = $A_RECORD->parseZone;
			}
			$label = $A_RECORD->getLabel;
			if (defined $label) {
			    unless ($label =~ /^failure/)  {
				if (defined $verbose) {
				    print "FOUR: $label\n";
				    $A_RECORD->printTokens;
				}
			    }
			}
		    }
		    else {	# label is something we don't care about
			unless ($label =~ /^failure/ ) {
			    if (defined $verbose) {
				print "FIVE: $label\n";
				$A_RECORD->printTokens;
			    }
			}
		    }
		}
		else {
		    if (defined $verbose) {
			print "SIX: $label\n";
			$A_RECORD->printTokens;
			print "\n";
		    }

		}
	    }
	    elsif ( $AUDIT_EVENT_ID eq 'chdir(2)' ) { # Chris thought this one was important
		$label = $A_RECORD->getLabel;
		if ($label eq 'path') {
		    $A_RECORD->parsePath;
		    # header-token,	path-token, [attr-token], [slabel-token] (object)
		    # [priv-token]	(if privilege used or required), subject-token	
		    # slabel-token	(subject), return-token
		}
	    }
	    elsif ( $AUDIT_EVENT_ID eq 'profile command' ) {
		my ($process_id,$effective_user_id,$real_user_id,$machine_id,$audit_session_id) = 
		    $A_RECORD->parseSubject;
		if ( ($effective_user_id eq 'metricnp') || ($real_user_id eq 'metricnp') ) {
		    if (defined $verbose) {
			print "C\n";
			print "$process_id,$effective_user_id,$real_user_id,$machine_id,$audit_session_id\n";
			$A_RECORD->printTokens;
		    }
		}

		if (exists ${$PROCESS_IDS}{$process_id} ) {
		    next RECORD;
		    if (defined $verbose) {
			print "PROFILE COMMAND:Process ID: $process_id exists \n";
			print "$process_id,$effective_user_id,$real_user_id,$machine_id\n";
			$A_RECORD->printTokens;
			print "\n";
		    }
		}
		elsif (exists ${$PARENT_PROCESS_IDS}{$audit_session_id} ) {
		    if (defined $verbose) {
			print "PROFILE COMMAND:Process ID: $process_id exists \n";
			print "$process_id,$effective_user_id,$real_user_id,$machine_id\n";
			$A_RECORD->printTokens;
			print "\n";
		    }
		}
	    }
	    elsif ($AUDIT_EVENT_ID eq 'cron-invoke')  {
		#header-token,subject-token,return-token,exec_args-token,text-token,(user name)		
		my ($process_id,$effective_user_id,$real_user_id,$machine_id,$audit_session_id) 
		    = $A_RECORD->parseSubject;
		if ( ($effective_user_id eq 'metricnp') || ($real_user_id eq 'metricnp') ) {
		    if (defined $verbose) {
			print "D\n";
			print "$process_id,$effective_user_id,$real_user_id,$machine_id,$audit_session_id\n";
			$A_RECORD->printTokens;
		    }
		}

		if (exists ${$PROCESS_IDS}{$process_id} ) {
		    next RECORD;
		    if (defined $verbose) {
			print "CRON INVOKE:Process ID: $process_id exists \n";
			print "$process_id,$effective_user_id,$real_user_id,$machine_id,$audit_session_id\n";
			$A_RECORD->printTokens;
			print "\n";
		    }
		}
		elsif (exists ${$PARENT_PROCESS_IDS}{$audit_session_id} ) {
		    if (defined $verbose) {
			print "CRON-INVOKE COMMAND:Process ID: $process_id exists \n";
			print "$process_id,$effective_user_id,$real_user_id,$machine_id,$audit_session_id\n";
			$A_RECORD->printTokens;
			print "\n";
		    }
		}
		${$PARENT_PROCESS_IDS}{$audit_session_id} = 1; # skip all children of this CRON parent process
	    }
	    elsif ( ($AUDIT_EVENT_ID eq 'setaudit_addr(2)') || ($AUDIT_EVENT_ID eq 'su') || ($AUDIT_EVENT_ID eq 'profile') || ($AUDIT_EVENT_ID eq 'p_online(2)') || ($AUDIT_EVENT_ID eq 'login - ssh') || ($AUDIT_EVENT_ID eq 'logout')  || ($AUDIT_EVENT_ID eq 'umount2(2)')  || ($AUDIT_EVENT_ID eq 'system booted') || ($AUDIT_EVENT_ID eq 'init(1m)') || ($AUDIT_EVENT_ID eq 'zoneadmd') || ($AUDIT_EVENT_ID eq 'setrlimit(2)') || ($AUDIT_EVENT_ID eq 'crontab-modify') || ($AUDIT_EVENT_ID eq 'mount(2)') || ($AUDIT_EVENT_ID eq 'login - local') || ($AUDIT_EVENT_ID eq 'login - zlogin') || ($AUDIT_EVENT_ID eq 'halt(1m)') || ($AUDIT_EVENT_ID eq 'sysinfo(2)') || ($AUDIT_EVENT_ID eq 'at-create atjob') || ($AUDIT_EVENT_ID eq 'passwd') || ($AUDIT_EVENT_ID eq 'getaudit_addr(2)')  ) {  
		my ($process_id,$effective_user_id,$real_user_id,$machine_id,$audit_session_id) 
		    = $A_RECORD->parseSubject;
		if ( ($effective_user_id eq 'metricnp') || ($real_user_id eq 'metricnp') ) {
		    if (defined $verbose) {
			print "E\n";
			print "$process_id,$effective_user_id,$real_user_id,$machine_id,$audit_session_id\n";
			$A_RECORD->printTokens;
		    }
		}

		if (exists ${$PROCESS_IDS}{$process_id} ) {
		    next RECORD;
		    if (defined $verbose) {
			print "$process_id,$effective_user_id,$real_user_id,$machine_id,$audit_session_id\n";
			print "$AUDIT_EVENT_ID:Process ID: $process_id exists \n";
			$A_RECORD->printTokens;
			print "\n";
		    }
		}
		elsif (exists ${$PARENT_PROCESS_IDS}{$audit_session_id} ) {
		    if (defined $verbose) {
			print "$AUDIT_EVENT_ID:Process ID: $process_id exists \n";
			print "$process_id,$effective_user_id,$real_user_id,$machine_id,$audit_session_id\n";
			$A_RECORD->printTokens;
			print "\n";
		    }
		}
	    }
	    elsif ($AUDIT_EVENT_ID eq 'invalid event number') {


	    }
	    else {
		unless ( exists ${$BAD_AUDIT_EVENT_ID}{$AUDIT_EVENT_ID} ) {
		    push @{$AUDIT_EVENT_IDS}, $AUDIT_EVENT_ID;
		    ${$BAD_AUDIT_EVENT_ID}{$AUDIT_EVENT_ID} = 1;
		}
		print "EIGHT:\n";
		$A_RECORD->printTokens;
		print "\n";

	    }
		
	}
	elsif ($label eq 'process') {
	    my ($process_id,$effective_user_id,$real_user_id,$machine_id,$audit_session_id) 
		= $A_RECORD->parseSubject;
	    if ( ($effective_user_id eq 'metricnp') || ($real_user_id eq 'metricnp') ) {
		if (defined $verbose) {
		    print "F\n";
		    print "$process_id,$effective_user_id,$real_user_id,$machine_id,$audit_session_id\n";
		    $A_RECORD->printTokens;
		}
	    }

	    $label = $A_RECORD->getLabel;
	    if ($label eq 'return') {
		my $error_status = $A_RECORD->parseReturn();
		unless (  $error_status eq 'success') {
		    next RECORD;
		}
	    }
	    $label = $A_RECORD->getLabel;
	    my $zone;
	    if ($label eq 'zone') {
		$zone = $A_RECORD->parseZone;
	    }
	    unless ( $A_RECORD->getTokenNum()  == 0 ) {
		die "Tokens have not all been processed";
	    }

	    #####################################################################
	    if (exists ${$PROCESS_IDS}{$process_id} ) {
		next RECORD;
		if (defined $verbose) {
		    print "$process_id,$effective_user_id,$real_user_id,$machine_id,$audit_session_id\n";
		    print "$label:Process ID: $process_id exists \n";
		    $A_RECORD->printTokens;
		    print "\n";
		}
	    }
	    elsif (exists ${$PARENT_PROCESS_IDS}{$audit_session_id} ) {
		if (defined $verbose) {
		    print "$label:Process ID: $process_id exists \n";
		    print "$process_id,$effective_user_id,$real_user_id,$machine_id,$audit_session_id\n";
		    $A_RECORD->printTokens;
		    print "\n";
		}
		next RECORD;
	    }

	    if ( $machine_id =~ /0.0.0.0/ ) {
		next RECORD;
		if (defined $verbose) {
		    print "0.0.0.0 matched\n";
		    print "PROCESS: Process ID: $process_id exists \n";
		    print "$process_id,$effective_user_id,$real_user_id,$machine_id\n";
		    $A_RECORD->printTokens;
		    print "\n\n\n";
		}
	    }
	}
	else {
	    if (defined $verbose) {
		print "first_record began with $label \n";
		$A_RECORD->printTokens;
	    }
	}
		
    }
    return $BSM_RECORD_OBJECT;
}


sub printSummaryReports {
    my $BSM_RECORD_OBJECT = shift;

    unless ( exists ${$BSM_RECORD_OBJECT}{'GOOD_COMMAND_ARGS'} ) {
	die "printSummaryReports was passed bad BSM_RECORD_OBJECT";
    }
    my $user_records = keys %{${$BSM_RECORD_OBJECT}{'GOOD_COMMAND_ARGS'}};
    my $command_records = keys %{${$BSM_RECORD_OBJECT}{'GOOD_USER_COMMAND_ARGS'}};
    if ( defined $verbose ) {
	    print "Printing output from [$user_records] user and [$command_records] command report records\n";
    }


    openOutFile($output_file); # see if output file exists
    
    #####################################################################################
    # COMMAND SUMMARY REPORTS                                                           #
    #####################################################################################
    print "COMMAND SUMMARY REPORTS\n";
    
    # COMMANDS..... run by user, which lists dates and arguments

    # what args are being used by users running commands 
    # @{${${${${${$BSM_RECORD_OBJECT}{'GOOD_COMMAND_ARGS'}}{$absolute_path}}{'USER_DATA'}}{$real_user_id}}{'arguments'}} = array of arguments


################################################################################################################
    foreach my $absolute_path ( sort keys %{${$BSM_RECORD_OBJECT}{'GOOD_COMMAND_ARGS'}}  ) {
	print "$absolute_path\n";
	# if command was used with an ARGUMENT

	# PRINT COMMAND ARGUMENTS AND THE NUMBER OF TIMES EACH PERSON USED THEM
	foreach my $arg ( keys %{${${${${$BSM_RECORD_OBJECT}{'GOOD_COMMAND_ARGS'}}{$absolute_path}}{'COMMAND_DATA'}}{'arguments'}} ) {
	    print "\t$arg\t";
	    my $real_user_id_count;
	    foreach my $real_user_id (sort @{${${${${${$BSM_RECORD_OBJECT}{'GOOD_COMMAND_ARGS'}}{$absolute_path}}{'COMMAND_DATA'}}{'arguments'}}{$arg}} ) {
		if (exists ${$real_user_id_count}{$real_user_id} ) {
		    ${$real_user_id_count}{$real_user_id}++;
		}
		else {
		    ${$real_user_id_count}{$real_user_id} = 1;
		}
	    }
	    foreach my $real_user (sort keys %{$real_user_id_count} ) {
		my $user_count = ${$real_user_id_count}{$real_user};
		print "$real_user($user_count):";
	    }
	    print "\n";
#	    my $arg_user_count = scalar (@{${${${${${$BSM_RECORD_OBJECT}{'GOOD_COMMAND_ARGS'}}{$absolute_path}}{'COMMAND_DATA'}}{'arguments'}}{$arg}});

	}

	print "\n";
	print "\t";
	foreach my $real_user_id (sort keys %{${${${$BSM_RECORD_OBJECT}{'GOOD_COMMAND_ARGS'}}{$absolute_path}}{'USER_DATA'}}  ) {
	    
	    print "$real_user_id";

	    my @Sorted_times =  sort { $a <=> $b } @{${${${${${$BSM_RECORD_OBJECT}{'GOOD_COMMAND_ARGS'}}{$absolute_path}}{'USER_DATA'}}{$real_user_id}}{'times'}};

	    my $first_time = $Sorted_times[0];
	    my $last_time = $Sorted_times[-1];

	    my ($fseconds, $fminutes, $fhours, $fday_of_month, $fmonth, $fyear, $fwday, $fyday, $fisdst) 
		= localtime($first_time);
	    my ($lseconds, $lminutes, $lhours, $lday_of_month, $lmonth, $lyear, $lwday, $lyday, $lisdst) 
		= localtime($last_time);
	    my $f_time = sprintf("%02d:%02d:%02d-%04d/%02d/%02d",
				 $fhours, $fminutes, $fseconds, $fyear+1900, $fmonth+1, $fday_of_month);
	    my $l_time = sprintf("%02d:%02d:%02d-%04d/%02d/%02d",
				 $lhours, $lminutes, $lseconds, $lyear+1900, $lmonth+1, $lday_of_month);
	    print "[$f_time to $l_time]";
# #	    my $user_count = scalar(@{${${${${${$BSM_RECORD_OBJECT}{'GOOD_COMMAND_ARGS'}}{$absolute_path}}{'USER_DATA'}}{$real_user_id}}{'times'}});

	}
	print "\n\n";
    }

############################################################################################################
    print "\nUSER SUMMARY REPORTS\n";
    # USER SUMMARY REPORTS
    # number of unique users who ran command, tracking arguments
    # @{${${${${$BSM_RECORD_OBJECT}{'GOOD_USER_COMMAND_ARGS'}}{$real_user_id}}{$absolute_path}}{'arguments'}}, $arg;
# how many commands did user run
    foreach my $real_user_id ( sort keys %{${$BSM_RECORD_OBJECT}{GOOD_USER_COMMAND_ARGS}}  ) {
	print "$real_user_id,";
	my $user_commands_count = 0;
	foreach my $absolute_path (sort keys %{${${$BSM_RECORD_OBJECT}{GOOD_USER_COMMAND_ARGS}}{$real_user_id}} ) {
#	    my $user_count = @{${${${${$BSM_RECORD_OBJECT}{'GOOD_USER_COMMAND_ARGS'}}{$real_user_id}}{$absolute_path}}{'times'}};
#	    print "$user_count:";
	    $user_commands_count++;
	}
	print "$user_commands_count\n";
    }


# 			# COMMANDS..... run by user, which lists dates and arguments
# 			push @{${${${${${$BSM_RECORD_OBJECT}{'GOOD_COMMAND_ARGS'}}{$absolute_path}}{'USER_DATA'}}{$real_user_id}}{'times'}}, $secs;
# 			# number of unique users who ran command, tracking time
# 			push @{${${${${$BSM_RECORD_OBJECT}{'GOOD_USER_COMMAND_ARGS'}}{$real_user_id}}{$absolute_path}}{'times'}}, $secs;
    closeOutFile($output_file); # close output_file
}

sub writeTimeStamp {
    open (OUTPUT, "> $$tracking_file") or die "can't open $tracking_file for writing: $!\n";
    flock (OUTPUT, 2) or die "can't flock $tracking_file $!\n";	
    close (OUTPUT) or die "can't close $tracking_file: $!\n";

}

sub openOutFile {
    my $output_file = shift;
    if (defined $output_file) {
	open (OUTPUT, "> $output_file") or die "can't open $output_file for writing: $!\n";
	flock (OUTPUT, 2) or die "can't flock $output_file: $!\n";	
	select OUTPUT;
	return "OPENED_OUTPUTFILE";
    }
    else {
	return "NO_OUTPUTFILE";
    }
}


sub closeOutFile {
    my $output_file = shift;

    if (defined $output_file) {
	if (-f $output_file) {
	    close (OUTPUT) or die "can't close $output_file: $!\n";
	}
    }
}

# CLASS PACKAGES

package AuditRecord;

use Time::Local;

sub new {
    my $class = shift;
    my $self = {};
    return bless $self, $class
}

sub audit_Init {
    my $self = shift;
    my @AUDIT_TOKENS = @_;
    $self->{'tokens'} = [@AUDIT_TOKENS];
}

sub parseHeader {
    my $self = shift;
    my ($record_byte_count,$version_num,$AUDIT_EVENT_ID,$event_modifier,$machinename,$time) 
	= splice( @{$self->{'tokens'}}, 0, 6); # !!! $time becomes available

    $self->{'AUDIT_EVENT_ID'} = $AUDIT_EVENT_ID;
#    $self->{'header'} = $token_ID;
    # Convert time to Ephoch Seconds;
    # 2008-11-10 02:35:02.242 -07:00
    my ($year,$month,$day,$hours,$minutes,$seconds) = 
	($time =~ /(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})/ );
    my $secs = timegm($seconds,$minutes,$hours,$day,$month-1, $year-1900 );
    $self->{'secs'} = $secs;
    return $AUDIT_EVENT_ID;
}

sub parsePath {
    my $self = shift;
    # *path-token*
    #header-token,subject-token,return-token,exec_args-token,text-token,(user name)
    my ($absolute_path)
	= splice ( @{$self->{'tokens'}} , 0, 1); # !!! absolute path becomes available
    $self->{'absolute_path'} = $absolute_path;
}

sub parseAttribute {
    my $self = shift;
    my ($file_access_mode,$owner_user_id,$owner_group_id,$file_system_id,$node_ID,$device_ID) 
	= splice( @{$self->{'tokens'}}, 0,6); # owner_user_id becomes available
}

sub parseExecArgs {
    my $self = shift;
    my $exec_args_count = shift @{$self->{'tokens'}};
    my @EXEC_ARGS = splice ( @{$self->{'tokens'}}, 0, $exec_args_count); # !!! arguments are captured
    $self->{'EXEC_ARGS'} = [@EXEC_ARGS];
}

sub parseSubject {
    my $self = shift;
    #######################################################################################
    # *subject token* has nine fields
    # capture terminal_id to know what trusted host user came from
    my ($audit_id,$effective_user_id,$effective_group_id,$real_user_id,
	$real_group_id,$process_id,$audit_session_id,$terminal_id) = 
	    splice (@{$self->{'tokens'}}, 0,8); # !!! get $real_user_id
    #######################################################################################
    # 9245 196634 th-cltpsc-02.East.Sun.COM
    # 0 0 0.0.0.0
    my ($device_id1,$device_id2,$machine_id) = split /[ ]/, $terminal_id;
    return ($process_id,$effective_user_id,$real_user_id,$machine_id,$audit_session_id);
}

sub parseReturn {
    my $self = shift;
    # *return token* has three fields
    my ($error_status,$return_value) = splice (@{$self->{'tokens'}}, 0,2);
    return $error_status;
}

sub parseZone {
    my $self = shift;
    # *zone token* has two fields
    my ($graph_zone) = splice (@{$self->{'tokens'}}, 0,1);
    return $graph_zone;
 }

sub printTokens {
    my $self = shift;
    foreach my $token ( @{$self->{'tokens'}} ) {
	print "$token,";
    }
    print "\n";
}

sub getArgString {
    my $self = shift;
    my $arg_string;
    foreach my $arg ( @{$self->{'EXEC_ARGS'}} ) {
	if ( defined $arg_string ) {
	    $arg_string .= " $arg";
	}
	else {
	    $arg_string = $arg;
	}
    }
    return $arg_string;
}

sub setArgs {
    my $self = shift;
    my (@ARGS) = @_;
    $self->{'EXEC_ARGS'} = [@ARGS];
}

sub getTokenNum {
    my $self = shift;
    return scalar(@{$self->{'tokens'}});
}

sub getLabel {
    my $self = shift;
    my $label = shift @{$self->{'tokens'}};
    return $label;
}
###############################################################################################

package AuditReport;

sub new {
    my $class = shift;
    my $self = {};
    return bless $self, $class
}

sub createGoodCommands {
    my $self = shift;
    my ($absolute_path,$secs,$real_user_id,$effective_user_id) = @_;
    push @{${${${${$self}{'GOOD_COMMAND_ARGS'}}{$absolute_path}}{'COMMAND_DATA'}}{'times'}}, $secs;

    # COMMANDS..... run by user, which lists dates and arguments
    push @{${${${${${$self}{'GOOD_COMMAND_ARGS'}}{$absolute_path}}{'USER_DATA'}}{$real_user_id}}{'times'}}, $secs;
    # COMMANDS..... run by user, listing effective user id
    ${${${${${$self}{'GOOD_COMMAND_ARGS'}}{$absolute_path}}{'USER_DATA'}}{$real_user_id}}{'effective_user_id'} = $effective_user_id;

    # number of unique users who ran command, tracking time
    push @{${${${${$self}{'GOOD_USER_COMMAND_ARGS'}}{$real_user_id}}{$absolute_path}}{'times'}}, $secs;
    ######################################################################################
    #
    # A command is always going to have some effective ID
    #
    # number of unique users who ran command, tracking effective user id
    ${${${${$self}{'GOOD_USER_COMMAND_ARGS'}}{$real_user_id}}{$absolute_path}}{'effective_user_id'} = $effective_user_id;

}

sub createGoodCommandArgs {
    my $self = shift;
    my ($absolute_path,$secs,$real_user_id,$effective_user_id,$arg_string) = @_;
    #COMMANDS..... run by user, which lists dates and arguments
    push @{${${${${${$self}{'GOOD_COMMAND_ARGS'}}{$absolute_path}}{'USER_DATA'}}{$real_user_id}}{'arguments'}}, $arg_string;
    # number of unique users who ran command, tracking arguments
    push @{${${${${$self}{'GOOD_USER_COMMAND_ARGS'}}{$real_user_id}}{$absolute_path}}{'arguments'}}, $arg_string;

    # capture common args for command
    # most common arguments 
    push @{${${${${${$self}{'GOOD_COMMAND_ARGS'}}{$absolute_path}}{'COMMAND_DATA'}}{'arguments'}}{$arg_string}}, "$real_user_id/$effective_user_id";

}
