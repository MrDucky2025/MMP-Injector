#pragma once
#include <Windows.h>
#include <iostream>
#include <stdio.h>
#include <stdint.h>
#include <vector>
#include <Psapi.h>
#include "Injection/Injection.h"
#include "ICHooker/ICHooker.h"
#include "NTDLL/ntdlldefs.h"
#include "ThreadPool/ThreadPool.h"
#include "WorkerFactory/WorkerFactory.h"
#include "Tools/Tools.h"
#include "SysCaller/SyscalCaller.h"

//int main(int argc,char ** argv);