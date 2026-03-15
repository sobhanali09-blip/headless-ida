---
description: IDA Pro 헤드리스 바이너리 분석 (idalib)
allowed-tools: Bash, Read, Write, Glob, Grep, Agent, TodoWrite
---

# IDA Headless 바이너리 분석 스킬

바이너리 분석 요청 시 이 워크플로우를 따르세요.

## 진입점
모든 IDA 작업은 `python tools/ida_cli.py` 명령어로만 수행합니다.
MCP나 다른 도구를 사용하지 않습니다.

## 워크플로우

### 1. 환경 확인 (최초 1회)
```bash
python tools/ida_cli.py --check
python tools/ida_cli.py --init
```

### 2. 인스턴스 시작
```bash
python tools/ida_cli.py start <바이너리_경로>
# 프로젝트 로컬에 IDB 저장 시:
python tools/ida_cli.py start <바이너리_경로> --idb-dir <프로젝트_디렉토리>
# 출력에서 instance_id 확인
python tools/ida_cli.py wait <id> --timeout 300
```
- .i64가 이미 있으면 자동 재사용 (수 초 완료)
- `--idb-dir`로 IDB 저장 경로를 프로젝트별로 지정 가능
- `--fresh`로 기존 .i64 무시하고 처음부터 분석
- `--force`로 동일 바이너리 중복 인스턴스 허용
- 분석 대기 중 다른 작업 가능

### 3. 초기 정찰
아래 순서로 바이너리 개요를 파악합니다:
```bash
# 기본 정보
python tools/ida_cli.py -b <hint> status
python tools/ida_cli.py -b <hint> imagebase
python tools/ida_cli.py -b <hint> segments

# 데이터 수집 (--out으로 컨텍스트 절약)
python tools/ida_cli.py -b <hint> strings --count 50 --out /tmp/strings.txt
python tools/ida_cli.py -b <hint> imports --count 50 --out /tmp/imports.txt
python tools/ida_cli.py -b <hint> exports --out /tmp/exports.txt
python tools/ida_cli.py -b <hint> functions --filter <keyword> --out /tmp/funcs.txt

# 함수가 많을 때 페이징
python tools/ida_cli.py -b <hint> functions --offset 100 --count 100
```
- `status`로 디컴파일러 사용 가능 여부, 함수 개수 먼저 확인
- `-b <hint>`로 바이너리 이름 일부만으로 인스턴스 자동 선택

### 4. 심층 분석
```bash
# 함수 찾기
python tools/ida_cli.py -b <hint> find_func <이름> [--regex]

# 디컴파일
python tools/ida_cli.py -b <hint> decompile <주소|이름> [--out /tmp/func.c]

# 일괄 디컴파일
python tools/ida_cli.py -b <hint> decompile_batch <addr1> <addr2> ... [--out /tmp/batch.c]

# 디스어셈블리
python tools/ida_cli.py -b <hint> disasm <주소|이름> --count 50

# 함수 상세 정보
python tools/ida_cli.py -b <hint> func_info <주소|이름>

# 크로스 레퍼런스
python tools/ida_cli.py -b <hint> xrefs <주소> --direction both

# 바이트 읽기
python tools/ida_cli.py -b <hint> bytes <주소> <크기>

# 바이트 패턴 검색
python tools/ida_cli.py -b <hint> find_pattern "48 8B ? ? 00" --max 20

# 주석 조회
python tools/ida_cli.py -b <hint> comments <주소>

# 사용 가능한 RPC 메서드 목록
python tools/ida_cli.py -b <hint> methods
```

### 5. 수정 & 반복 분석
```bash
python tools/ida_cli.py -b <hint> rename <주소> <새이름>
python tools/ida_cli.py -b <hint> set_type <주소> "int __fastcall func(int a, int b)"
python tools/ida_cli.py -b <hint> comment <주소> "설명 텍스트"
python tools/ida_cli.py -b <hint> save
```
> **반복 분석 패턴**: rename/set_type 적용 후 다시 decompile하면 변수명과 타입이
> 반영되어 훨씬 읽기 쉬운 코드가 됩니다. 핵심 함수는 이 과정을 반복하세요.

### 6. 종료
```bash
python tools/ida_cli.py stop <id>
```

## 멀티 인스턴스 워크플로우

메인 바이너리와 라이브러리를 동시에 분석할 때:
```bash
# 두 바이너리를 각각 시작
python tools/ida_cli.py start ./main_binary
python tools/ida_cli.py start ./libcrypto.so

# -b 힌트로 각각 지정하여 분석
python tools/ida_cli.py -b main decompile 0x401000
python tools/ida_cli.py -b crypto decompile 0x12340

# 인스턴스 목록 확인
python tools/ida_cli.py list
```

## 분석 전략

### 문자열 추적 패턴 (가장 기본적인 RE 기법)
가장 빠르게 목표 코드에 도달하는 방법:
1. `strings --filter <키워드>` → 의심 문자열 발견
2. `xrefs <문자열_주소>` → 해당 문자열을 사용하는 코드 위치
3. `decompile <xref_주소>` → 호출 함수 분석
4. 필요 시 xrefs를 다시 추적 (callers of callers)

### 보안 솔루션 분석 시
1. strings/imports로 보안 관련 키워드 검색 (root, jailbreak, ssl, cert, integrity, frida, xposed, magisk 등)
2. find_func로 관련 함수 목록 확인
3. decompile로 핵심 함수 분석
4. xrefs로 호출 관계 추적
5. rename/set_type/comment로 분석 결과 기록 → 다시 decompile

### 펌웨어/IoT 분석 시
1. `segments`로 메모리 레이아웃 파악 (ROM/RAM 영역 구분)
2. `strings`로 디바이스 식별 정보, 명령어, 프로토콜 키워드 검색
3. `find_func --regex "uart|spi|i2c|gpio"` → 하드웨어 인터페이스 함수
4. `exports`로 공개 심볼 확인 → 주요 진입점 파악
5. `find_pattern`으로 매직 바이트/구조체 헤더 검색

### 취약점 연구 시
1. imports에서 위험 함수 검색 (memcpy, strcpy, sprintf, system, exec 등)
2. 각 위험 함수에 대해 `xrefs` → 호출 위치 파악
3. `decompile`로 호출 컨텍스트 분석 (버퍼 크기, 입력 검증 여부)
4. `func_info`로 함수 크기/인자 확인
5. `bytes`로 스택 버퍼 크기와 오프셋 확인

### 멀웨어 분석 시
1. `strings`로 C2 도메인, IP, 레지스트리 키, 파일 경로 검색
2. imports에서 네트워킹 (socket, connect, send), 파일 조작, 프로세스 주입 API 확인
3. `find_func --regex "crypt|encode|decode|xor"` → 암호화/인코딩 루틴
4. `decompile_batch`로 의심 함수들 일괄 분석
5. `find_pattern`으로 하드코딩된 키/IV/XOR 테이블 검색

### 대용량 결과 처리
- 항상 `--out` 옵션으로 파일 저장 후 Read로 읽기
- `--count`, `--filter`로 결과 범위 제한
- `--offset`으로 페이징 (대량 함수 탐색 시)
- `--json` 모드로 구조화된 데이터 활용

## 에러 대응
- 분석 실패 시: `python tools/ida_cli.py logs <id> --tail 20`
- .i64 손상/잠김 시 (`open_database returned 2`): 기존 .i64 삭제 후 `--fresh`로 재시작
- .i64 재생성: `python tools/ida_cli.py start <binary> --fresh`
- 인스턴스 목록: `python tools/ida_cli.py list`
- 정리: `python tools/ida_cli.py cleanup`

## 판단 기준: IDA vs 다른 도구
- Java/Kotlin 코드 → JADX
- 간단한 .so 확인 → Ghidra
- 보안 솔루션 핵심 로직, Ghidra 결과 불명확 → **IDA CLI 사용**
- 멀티 아키텍처 (ARM/MIPS/PPC/V850/ARC) → **IDA CLI 사용**
- 펌웨어/IoT 바이너리 → **IDA CLI 사용**

## 사용자 인자: $ARGUMENTS
사용자가 `/ida <바이너리 경로>` 형태로 호출하면 해당 바이너리에 대해 즉시 분석을 시작합니다.
바이너리 경로가 제공되지 않으면 사용자에게 분석 대상을 확인합니다.
