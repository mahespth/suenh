
import fork

#fork.call('ksh')

#print('\tstdout: called fork')


p = fork.Popen('ksh', stdout=fork.subprocess.PIPE)

print("\tmade it here")
output, error = p.communicate()
#print(p.pid
print("\tstdout=", str(output) )
print("\treturn code=", str( p.returncode))
