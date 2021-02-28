# Dummy system to learn about logging activity

### logging_with_count.py

'''
import time
def logging():
    f.write('Username : '+username+'\n')
    f.write('Password : '+password+'\n')
    f.write('Date/Time %s' %(time.strftime('%Y-%m-%d %H:%M:%S'))+'\n')
print('Welcome to dummy system')
count = 0
while count < 3:
    username = input('Username : ')
    password = input('Password : ')
    if username == 'admin' and password =='1234':
        f = open('dummy.log','a')
        f.write('Login Success'.center(40,'#')+'\n')
        logging()
        f.write('#'*40+'\n')
        f.close()
        print('Login Successful')
        break
    else:
        count += 1
        f = open('dummy.log','a')
        f.write('Login Error'.center(40,'!')+'\n')
        logging()
        f.write('!'*40+'\n')
        f.close()
        print('Login Failed ('+str(count)+')')
'''
