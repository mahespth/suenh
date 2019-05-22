#!/usr/bin/env python3

"""suenh: Enhanced SUDO Controls, Stephen Maher (steve@aixtreme.org), 2018 V01.01 """

# https://docs.python.org/2/library/defprocess.html
# not working in 3. so going to v3
# https://docs.python.org/3.4/library/subprocess.html
############################################################
#from defprocess import call

import os
import platform
import subprocess


# We will be trapping control c and some other bits
############################################################
import signal

# We need the password database tools to map uid/guid etc.
############################################################
import pwd

import sys

# https://docs.python.org/2/library/shlex.html
import shlex

# https://docs.python.org/2/library/syslog.html#module-syslog
############################################################
import syslog

import argparse
import getopt
import copy               # will be used in defs ie workingRef = copty.copy(/deepcopy)(refPassed)
import pprint             # will be used for pretty printing of debug information.

import unittest

# We are going to need a lot of testing a debug so lets make sure we start off with a decent
# way to debug all this.
# https://pymotw.com/2/sys/tracing.html
# again not working in v3 - so needs some reworking.
##################################################
def trace_calls(frame, event, arg):
    if event != 'call':
        return

    co = frame.f_code
    func_name = co.co_name

    if func_name == 'write':
        # Ignore write() calls from print statements
        return

    func_line_no = frame.f_lineno
    func_filename = co.co_filename
    caller = frame.f_back
    caller_line_no = caller.f_lineno
    caller_filename = caller.f_code.co_filename
    print('Call to %s on line %s of %s from line %s of %s' % \
        (func_name, func_line_no, func_filename,
         caller_line_no, caller_filename ))

    return

def execCommand(useShell,logResults,commandLine):

    returnCode = -1     # if you ever get this then something is seriously wrong.

    # Parse the arguments checking for anything now allowed
    command_args = shlex.split(commandLine)

    if logResults == True:
        # We are not there yet..
        proc = subprocess2.Popen(command_args,
            stdout=subprocess.PIPE,
            )

        stdout_value = proc.communicate()[0]
        returnCode = proc.returncode

        print('\tstdout:', repr(stdout_value) )
        print('\tstdout:', proc_erc)
    else:
        returnCode = subprocess.call(command_args,shell=True)
        print('\treturn:', proc)

    return returnCode

# Here we will change to the new user and pass over the same requirements
def execSUDO(targetUser):

    return

# Here we check that you are able to execute SUDO and its
# configured to run the desired function
def parseSUDO(targetCommand):

    return



def signalHandler_controlC(signal, frame):
    print('User Initiated Exit')
    sys.exit(0)

def _opsConfig():
    return True

def _saveERC():
    return True

def _documentation_1():
    return True

def _saveERC():
    return True

def _restoreERC():
    return True
# function to resolve the links is nice and clean

def _resolve_link():

    return True

def _documentation_2():
    return True

def _documentation_3():
    return True

def errorMessage( messageContent ):

    print('[E]' + str( messageContent) )
    loggerError( str(messageContent) )

    return True

def infoMessage( messageContent ):

    print('[I]' + str(messageContent))
    logger( str(messageContent) )

    return True

def subUpdateProfile():
    print('Updating Profile for USER '+str(USER))

    return True

def _opsConfig():
    return True


def subSUDOconfigure():
    print('Updating SUDO configuration.')

    return True

def subSUDOunconfigure():
    print('Updating SUDO configuration.')

    return True

# Here we are going to un-configure the application links should we require them.
# where the ksh version cheats and takes the configuration from the script as
# an input file we will actually use the configuration parsing to do it correctly.
def _unconfigureLinks():
    return True



# Here we are going to configure the application links should we require them.
# where the ksh version cheats and takes the configuration from the script as
# an input file we will actually use the configuration parsing to do it correctly.
def _configureLinks():
    return True

def _getopts_long():
    return True

def _usage():
    return True

def logger(messageString):
    syslog.openlog(suenhAppName,logoption=syslog.LOG_PID, facility=syslog.INFO)
    syslog.syslog(messageString)
    return True

def loggerError(messageString):
    syslog.openlog(suenhAppName,logoption=syslog.LOG_PID, facility=syslog.LOG_ERR)
    syslog.syslog(messageString)
    return True

# ensure we capture Control-C
############################################################
def _trapcntrlc():

    signal.signal(signal.SIGINT, signalHandler_controlC)
    return True

def _debugVars():
    return True

# Return the user that logged into first to this tty
def returnInitialLogin():
    # USERttyshort
    # need to translate this
    #@@SGM if aix then -Xft needed for long usernames

    if platform.system() == "Darwin":
        commandLine='/bin/ps -ft${TTYNUM} -ouser= 2>/dev/null | grep -wv root'
    elif platform.system() == "AIX":
        commandLine='/usr/bin/ps -Xft${TTYNUM} -ouser= 2>/dev/null | grep -wv root'
    else:
        commandLine='/usr/bin/ps -ft${TTYNUM} -ouser= 2>/dev/null | grep -wv root'

    # | awk '$1 != "'$USER'" { print $1; exit }')'
    output = subprocess.check_output(commandLine,stderr=subprocess.STDOUT)

def debugMessage(messageContent):
    if suenDebug == 'on':
        print('[D] '+str(messageContent),file=sys.stderr)
    return



def checkPermissions(inputFile,inputOwner,inputOctalMask):
    # Check file exists and matches owner

    debugMessage( 'InputFile='+str(inputFile)+', inputOwner='+str(inputOwner) )
    try:
        st = os.stat( inputFile )
    except FileNotFoundError:
        debugMessage('os.stat returned None')
        return False

    if st == None:
            debugMessage('os.stat returned None')
            return False

    if pwd.getpwuid(st.st_uid).pw_name != inputOwner:
        debugMessage('File owned by '+str(pwd.getpwuid(st.st_uid).pw_name)+' not '+inputOwner)
        return False



    return True

# are the options valid ?? lets hope this honours enough of POSIX getopts.
############################################################
def optionParse(configurableOptions,usersOptions):

    # https://docs.python.org/3/library/getopt.html?highlight=getopt#module-getopt
   ############################################################

    try:
            options,remainder = getopt.getopt(usersOptions,configurableOptions)

    except getopt.GetoptError as err:
            errorMessage('Invalid or Insecure option for specified command.')
            return False

    return True

# Return the remaining portion of the parsed command line
############################################################
def optionRemainder(configurableOptions,usersOptions):

    try:
            options,remainder = getopt.getopt(usersOptions,configurableOptions)

    except getopt.GetoptError as err:
            return None

    return remainder




# Start to declare globals
############################################################
suenhAppName='suenh'
ttynum=''                       # result from tty command
ttyid=''                        # user first logged in as this user
visauser=''                     # Needed for backwards customer compatibility, could do this differently !?


# Paranoid? moi?
############################################################
os.unsetenv('CDPATH')
os.unsetenv('LIBPATH')
os.unsetenv('MANPATH')
os.unsetenv('LD_PRELOAD')

USERuid=os.getuid()            # We need to understand who you are
USERgid=os.getgid()            # and what your assigned to.
USEReuid=os.geteuid()
USERegid=os.getegid()
USERgroups=os.getgroups()       # List of groups for later comparison
USERtty=os.ttyname(0)            # Users $( tty )
USERttyshort=USERtty.split('/')[-1]

USERpwd=pwd.getpwuid(USERuid)   # data struct of user info
                                # ie pwd.struct_passwd(pw_name='mahespth', pw_passwd='********', pw_uid=501, pw_gid=20, pw_gecos='STEPHEN Maher', pw_dir='/Users/mahespth', pw_shell='/bin/bash')


storeOutput=False               # Configurable but will ensure its always set


# We always want to know where we are putting out tertiary files
############################################################

temporaryDirectory = os.getenv('TMPDIR','/tmp')
os.environ['TMPDIR'] = temporaryDirectory

suenDebug = os.getenv('SUENH_DEBUG','off')

if suenDebug == 'on':
    if checkPermissions(temporaryDirectory+str('/.suenh_debug'),'root','022') == False:
        print('FATAL SECURITY ERROR - DEBUGGING IS DISABLED')
        exit(1)
    else:
     # tracing disabled until v3 tracing code is working
     # sys.settrace(trace_calls)
     debugMessage('Debug on')

# also need to check its not suid

if platform.system() == "Darwin":
    # OSX - likely mine, lets change the tests

    if checkPermissions( __file__, USERpwd.pw_name,'022') == False:
        print('FATAL SECURITY ERROR - CHECK PERMISSIONS', file=sys.stderr)
        #exit(1)
else:
    if checkPermissions( __file__, 'root','022') == False:
        print('FATAL SECURITY ERROR - CHECK PERMISSIONS', file=sys.stderr)
        exit(3)

if checkPermissions('/etc/profile', 'root','022') == False :
        print('FATAL SECURITY ERROR - CHECK PERMISSIONS', file=sys.stderr)
        exit(5)

if platform.system() == "AIX":
    if checkPermissions('/etc/environment', 'root','022') == False :
        print('FATAL SECURITY ERROR - CHECK PERMISSIONS', file=sys.stderr)
        exit(7)


# We reset these as SUDO can change them.
# we need to eval the "~" as this can fail in install
# or background attempts at running the commands
############################################################
USER=os.getenv('USER')
SUDO_USER=os.getenv('SUDO_USER')
SUDO_COMMAND=os.getenv('SUDO_COMMAND')


if USER == None:
    USER=subprocess.check_output('/usr/bin/whoami')
    #USER=call('/usr/bin/whoami',shell=False)


SUDO_USER=os.getenv('SUDO_USER')

if SUDO_USER == USER:
    errorMessage('You need to be logged into your own account to execute this command.')
    exit(127)

if USER == None:
    errorMessage('Unable to identify user.')
    exit(127)

# Parse arguments - we may have to do this manually as a non-root user due to the comlexity...

parser = argparse.ArgumentParser()



#parser.add_argument('-h','--help')

if USER == 'root' and SUDO_USER == None:
    """We are running as admin, and are running config tasks."""

    parser.add_argument('-p', '--update-profile', help='Update USERS shell profile to include opsbin in USERS path.',action='store_true')
    parser.add_argument('-c','--configure',help='Configure all suenh links in /usr/local/bin',action='store_true')
    parser.add_argument('-C','--unconfigure',help='Remove all suenh links in /usr/local/bin',action='store_true')
    parser.add_argument('-s','--sudoconfigure',help='Enable global execution to suenh from SUDO command.',action='store_true')
    parser.add_argument('-S','--sudounconfigure',help='Remove global execution to suneh from SUDO command.',action='store_true')
    parser.add_argument('-o','--opsbinconfig',help='Update all links in opsbin.',action='store_true')

    args = parser.parse_args()

    if args.update_profile:
        exit(subUpdateProfile())

    if args.configure:
        print('I would run configure')

    if args.unconfigure:
        print('I would run un-configure')

    if args.sudoconfigure:
        exit(subSUDOconfigure())

    if args.sudounconfigure:
        exit(subSUDOconfigure())

    if args.opsbinconfig:
        print('I would run opsbin config')


if USER != 'root' and SUDO_USER != None:
    """We have been called via SUDO and are in high secure and paranoid mode"""

    args = parser.parse_args()

    commandLine='/bin/bash'
    execCommand(True,False,commandLine)

if USER != 'root' and SUDO_USER == None:
    """We are in user configuration mode"""

    # here we have to go old school to parse the input.
    # question is - can we call getopts like we could in the shell to validate
    # the input
    #parser.add_argument('-p', '--updateprofile', help='Update USERS shell profile to include opsbin in USERS path.')
    #parser.add_argument('-ll','--list',help='List objects that are accessable.',action='store_true')

    args = parser.parse_args()
    if args.list:
        print('We would list everything you have access to')

print('Am still here...')


#if __name__ == '__main__':
#    if arg
#    parser = argparse.ArgumentParser()
#    parser.add_argument('-o', '--output')
#    parser.add_argument('-v', dest='verbose', action='store_true')
#    args = parser.parse_args()
#    # ... do something with args.output ...
#    # ... do something with args.verbose ..



