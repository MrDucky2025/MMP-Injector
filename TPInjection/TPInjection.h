#pragma once
#include <Windows.h>
#include <iostream>
#include <stdio.h>
#include <stdint.h>
#include <vector>
#include "../NTDLL/ntdlldefs.h"
#include "../ThreadPool/ThreadPool.h"
#include "../WorkerFactory/WorkerFactory.h"
#include "../Tools/Tools.h"
#include "../TPInjection/TPInjection.h"
#include "../SysCaller/SyscalCaller.h"
#include "../ICHooker/ICHooker.h"


bool CreateTPDirectThread(HANDLE process, void* addr);