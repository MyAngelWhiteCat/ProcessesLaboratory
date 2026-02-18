# Разработка в процессе.

Утилита для анализа активных процессов на аномалии.

## Реализованный функционал:
- Сбор информации о процессах двумя способами - ToolHelp и Nt
- Поиск скрытых процессов (Базовый)
- RWX сканнер 

## Current task:
- Разработка Application - прослойки между лабараторией и UI, предоставляющей интерфейс для интеграции любого удобного UI
- Разработка демонстративного UI с использованием WINAPI WinMain WndProc цикла.

### Бэклог
-

## TODO:


### Фича - UI
- Реализован простейший демонстративный UI с использоваием WinMain WndProc 

### Фичи - Анализаторы
- Скачки потребления ресурсов
- Подозрительные интернет соединения
- Скрытые процессы
- Подозрительные пути исполняемых файлов
- Инжектированный код в памяти
- Процессы с изменяющимися именами
- Необычные DLL модули
- Повышенные привилегии
- Аномальное время работы
- Процессы без цифровой подписи
- ...

# Используемая документация:
Будет заполняться по мере прогресса. Не остортированна ни по какому признаку.

[ProcessEntry32](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32-processentry32)

[openprocess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess)

[process-security-and-access-rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)

[taking-a-snapshot-and-viewing-processes](https://learn.microsoft.com/en-us/windows/win32/toolhelp/taking-a-snapshot-and-viewing-processes)

[getprocesstimes](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocesstimes)

[getprocessmemoryinfo](https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getprocessmemoryinfo)

[queryfullprocessimagenamew](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-queryfullprocessimagenamew)

[gettokeninformation](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation)

[createtoolhelp32snapshot](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot)

[moduleentry32](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32-moduleentry32)

[threadentry32](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32-threadentry32)

[getpriorityclass](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getpriorityclass)

[ntquerysysteminformation](https://learn.microsoft.com/ru-ru/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation)

[enumprocesses](https://learn.microsoft.com/ru-ru/windows/win32/api/psapi/nf-psapi-enumprocesses)

[getmodulehandlew](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlew)

[getprocaddress](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress)

[virtualqueryex](https://learn.microsoft.com/ru-ru/windows/win32/api/memoryapi/nf-memoryapi-virtualqueryex)

[memory_basic_information](https://learn.microsoft.com/ru-ru/windows/win32/api/winnt/ns-winnt-memory_basic_information)

[getsysteminfo](https://learn.microsoft.com/ru-ru/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsysteminfo)

[system_info](https://learn.microsoft.com/ru-ru/windows/win32/api/sysinfoapi/ns-sysinfoapi-system_info)

[getmappedfilenamea](https://learn.microsoft.com/ru-ru/windows/win32/api/psapi/nf-psapi-getmappedfilenamea)

[enumprocessmodules](https://learn.microsoft.com/ru-ru/windows/win32/api/psapi/nf-psapi-enumprocessmodules)
