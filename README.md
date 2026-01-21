# Это не готовое ПО. Разработка в процессе.

Простейшая утилита для анализа активных процессов на аномалии.

## Current task:
- Разработка ядра сбора информации о процессах

## TODO:
- Скачки потребления ресурсов
- Подозрительные интернет соединения
- Скрытые процессы
- Подозрительные пути исполняемых файлов
- Инжектированный код в памяти
- Процессы с изменяющимися именами
- Необычные DLL модули
- Повышенные привилегии
- Аномальное время работы
- Скрытые сетевые соединения
- Процессы без цифровой подписи
- Быстро перезапускающиеся процессы
- ...

#Используемая документация:
https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32-processentry32
https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights
https://learn.microsoft.com/en-us/windows/win32/toolhelp/taking-a-snapshot-and-viewing-processes
https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocesstimes
https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getprocessmemoryinfo
https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-queryfullprocessimagenamew
https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation
https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot
https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32-moduleentry32
