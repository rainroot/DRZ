# 반가워요. Drizzle VPN입니다.!

안녕하세요. **Drizzle VPN** 개발자 **#rainroot**입니다. **Drizzle VPN**은  **OpenVPN**의 **프로토콜**을 사용하고 **OpenVPN**의 소스 구조와 유사하게 개발하였습니다. 

**Drizzle VPN**은 다음과 같은 특징이 있습니다.

- 멀티스레딩

  > Worker Thread : 암호화 / 복호화 및 라우팅 담당
  >
  > 최소 1개에서 최대 CPU core 수 * 2

- 리눅스 전용

  > **Drizzle VPN **은 리눅스 전용 프로그램입니다. 윈도우나 기타 OS는 지원하지 않아요.
  >
  > 하지만, **OpenVPN**과 통신이 가능해서 MS윈도우,MAC,안드로이드등의 **OpenVPN** 앱을 그대로 사용할 수 있어요.

* 아직은 미완성

  > 현재 32st 버전은 시험단계에요. 아직은 미완성이죠. 
  >
  > VPN 기능은 안정적으로 동작 하지만,  관리 유틸을 지속적으로 개발 진행 중이에요.
  >
  > 앞으로의 계획에서 자세히 볼수 있습니다.



# 성능 비교 [ Drizzle VS OpenVPN ]

- Drizzle VPN [ Bridge Mode ]

  ```mermaid
  classDiagram
  Class01 <|-- AveryLongClass : Cool
  Class03 *-- Class04
  Class05 o-- Class06
  Class07 .. Class08
  Class09 --> C2 : Where am i?
  Class09 --* C3
  Class09 --|> Class07
  Class07 : equals()
  Class07 : Object[] elementData
  Class01 : size()
  Class01 : int chimp
  Class01 : int gorilla
  Class08 <--> C2: Cool label
  ```

|      |      |      |
| ---- | ---- | ---- |
|      |      |      |
|      |      |      |
|      |      |      |



## 내부 멀티스레딩 구조





## 컴파일 방법



## 사용방법



## 설정파일 추가 옵션




# 앞으로의 계획


