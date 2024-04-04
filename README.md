### Syscall Hooking 

### Infinity Hook ( 이하 IH 라 칭하겠습니다. )
"Hook system calls, context switches, page faults, DPCs and more."   
위 마법은 후킹은 어떻게 이루어지는지 알아보겠습니다. 그 전에, 먼저 Etw에 대해 간단하게 알아봅시다.   
Etw(Event-Trace-Windows)는 윈도우에서 발생하는 모든 이벤트를 추적하고 기록할 수 있게 해줍니다. 

usermode syscall -> KiSystemCall64(or KiSystemCall64Shadow) -> PerfInfoLogSysCallEntry -> EtwTraceSiloKernelEvent -> EtwpLogKernelEvent -> and more ...

PerfInfoLogSysCallEntry가 호출되는 부분을 잠깐 살펴봅시다.    
아래 함수(KiSystemCall64 함수의 끝 부분)를 잘 기억해두세요. 
![PerfInfoLogSyscallEntry](https://github.com/passion1337/syscallHook/assets/162768394/5339ba9a-d1f4-4b17-a61f-7799759bf173)
   
ms  공식 문서(https://learn.microsoft.com/ko-kr/windows/win32/etw/wnode-header)
에 따르면, 아래 값에 따라 "이벤트에 대한 TimeStamp"를 Logging 한다고 하였습니다.    
``` c 
PWNODE_HEADER->ClientContext 
if(PWNODE_HEADER->ClientContext==1) QPC(쿼리 성능 카운터)   
if(PWNODE_HEADER->ClientContext==2) System Time 
if(PWNODE_HEADER->ClientContext==3) CpuCycle, 리소스를 가장 적게 사용함, etc..
```
  
커널에서 Etw를 활성화 하려면 ZwTraceControl로 추적 세션을 생성해야합니다.
이것이 생성 될 때, WMI_LOGGER_CONTEXT 라는 구조체도 생성됩니다. 

``` c 
// Before win10 2004
struct _WMI_LOGGER_CONTEXT
{
    ULONG LoggerId;                                                         //0x0
    ULONG BufferSize;                                                       //0x4
    ULONG MaximumEventSize;                                                 //0x8
    ULONG LoggerMode;                                                       //0xc
    LONG AcceptNewEvents;                                                   //0x10
    ULONG EventMarker[2];                                                   //0x14
    ULONG ErrorMarker;                                                      //0x1c
    ULONG SizeMask;                                                         //0x20
    LONGLONG (*GetCpuClock)();                                              //0x28
	...
} 
``` 
offset 0x28에 들어있는 function pointer가 보이시나요 ? IH는 이 함수포인터를 Hijacking 합니다. 아마 ClientContext 값에 종속적이게 위 함수 포인터가 설정됐을 걸로 예상할 수 있습니다. 하지만 아쉽게도 IH가 출시된 이후에 얼마되지 않아서 위 멤버를 함수포인터가 아니라 Flag로 바꿔버렸습니다.

```c
// after win10 2004
struct _WMI_LOGGER_CONTEXT
{
    ULONG LoggerId;                                                         //0x0
    ULONG BufferSize;                                                       //0x4
    ULONG MaximumEventSize;                                                 //0x8
    ULONG LoggerMode;                                                       //0xc
    LONG AcceptNewEvents;                                                   //0x10
    ULONG EventMarker[2];                                                   //0x14
    ULONG ErrorMarker;                                                      //0x1c
    ULONG SizeMask;                                                         //0x20
    ULONGLONG GetCpuClock;                                                  //0x28
	...
}
``` 
실제로 디버깅 해 보니 제 시스템에선 3이 들어가있었고, 함수포인터를 넣으니 bsod를 만났습니다. 
타임스탬프는 EtwpReserveTraceBuffer 라는 함수 안에서 기록됩니다. EtwpReserveTraceBuffer를 Ida로 살펴보면 아래같은 코드가 나옵니다. 

```c
      v17 = *((_QWORD *)a1 + 5);	// (QWORD*)a1 + 5 == _WMI_LOGGER_CONTEXT.GetCpuClock 
      if ( v17 > 3 )
        goto LABEL_70;
      if ( (_DWORD)v17 == 3 )		
      {
        v18.QuadPart = __rdtsc();
      }
      else if ( (_DWORD)v17 )
      {
        v24 = v17 - 1;
        if ( v24 )
        {
          if ( v24 != 1 )
LABEL_70:
            __fastfail(0x3Du);
          v40.QuadPart = 0i64;
          ((void (__fastcall *)(LARGE_INTEGER *, __int64, __int64))off_140C009E0[0])(&v40, a2, v9);
          v18 = v40;
          v9 = v36;
          v8 = v35;
        }
        else                                     
        {
          v18 = KeQueryPerformanceCounter(0i64);
          v9 = v36;
          v8 = v35;
        }
      }
      else
      {
        v18.QuadPart = RtlGetSystemTimePrecise();
        v9 = v36;
        v8 = v35;
      }
``` 
논리가 보이시나요 ? v17에 GetCpuClock값을 얻어와서 이를 기준으로 분기하고있습니다. 
```c
if(v17 > 3) __fastfail(0x3Du);
if(v17 == 3) v18 = __rdtsc(); 
if(v17 == 2) 
{
	v40.QuadPart = 0i64;
    ((void (__fastcall *)(LARGE_INTEGER *, __int64, __int64))off_140C009E0[0])(&v40, a2, v9);
    v18 = v40;
}
if(v17 == 1) v18 = KeQueryPerformanceCounter(0i64);
if(!v17) v18 = RtlGetSystemTimePrecise(); 
``` 
위에서 언급한 ( ClientContext==3일때, CpuCycle을 사용한다고 언급 ) 사실과 일치합니다. 함수포인터를 대입했을 때 일어났던 bsod도 이것 때문이었습니다.
- 만약 v17==2일때 사용되는 off_140C009E0의 포인터가 pg를 트리거 하지 않는다면 이를 하이재킹해도 될거같습니다. 
- 또 v17==1(KeQueryPerformanceCounter)일 때도 공략할 포인트가 존재합니다. 

```c 
v2 = HalpPerformanceCounter;
v9 = (*(__int64 (__fastcall **)(__int64))(v2 + 0x70))(v8); 
``` 
KeQueryPerformanceCounter 함수 안에서 이런식으로 v2 + 0x70 으로 함수포인터를 사용하는 것이 보입니다.   
이제 후킹 함수를 작성할 차례인데,  IH는 이 말도 안되는 일을 스택워킹 + PerfInfoLogSysCallEntry 이후의 호출 특성을 이용해 해결합니다.   
PerfInfoLogSysCallEntry에서 아래 함수를 호출합니다. 두개의 상수가 보이시나요 ? 
```c
EtwTraceSiloKernelEvent(ThreadServerSilo, (int)someArray, 1, 0x40000040u, 0xF33, 0x501802); 
``` 
0xF33, 0x0x501802 라는 상수를 발견할 때 까지 "스택을 서치"하고, PerfInfoLogSysCallEntry 호출 이후에 호출될(call rax) SysCall 주소의 오프셋을 계산하여 이를 덮어씁니다.   
또 최대한 Universal 하게 동작하기 위해서 Kva Shadow를 사용하는 시스템도 고려한 코드가 보입니다. 원본 IH를 읽어보세요. 


### resuilt 
![result](https://github.com/passion1337/syscallHook/assets/162768394/bfcdad7b-8de5-42ca-a61e-11ee55905ff5)


### references 
<url>https://github.com/everdox/InfinityHook</url>   
<url>https://www.unknowncheats.me/forum/anti-cheat-bypass/561736-analyzing-easyanticheats-cr3-protection.html</url>

