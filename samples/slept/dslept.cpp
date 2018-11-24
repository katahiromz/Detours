//////////////////////////////////////////////////////////////////////////////
//
//  Detour Test Program (dslept.cpp of dslept.dll)
//
//  Microsoft Research Detours Package
//
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//
//  An example dynamically detouring a function.
//
#include <stdio.h>
#include <windows.h>
#include "detours.h"
#include "slept.h"

#include "verify.cpp"

LONG dwSlept = 0;

static DWORD (WINAPI * TrueSleepEx)(DWORD dwMilliseconds, BOOL bAlertable) = NULL;
static int (WINAPI * TrueEntryPoint)(VOID) = NULL;
static int (WINAPI * RawEntryPoint)(VOID) = NULL;

extern "C"
DWORD WINAPI UntimedSleepEx(DWORD dwMilliseconds, BOOL bAlertable)
{
    if (TrueSleepEx != NULL) {
        return TrueSleepEx(dwMilliseconds, bAlertable);
    }
    return 0;
}

extern "C"
DWORD WINAPI TimedSleepEx(DWORD dwMilliseconds, BOOL bAlertable)
{
    DWORD dwBeg = GetTickCount();
    DWORD ret = TrueSleepEx(dwMilliseconds, bAlertable);
    DWORD dwEnd = GetTickCount();

    InterlockedExchangeAdd(&dwSlept, dwEnd - dwBeg);
    return ret;
}

extern "C"
DWORD WINAPI GetSleptTicks(VOID)
{
    return dwSlept;
}

extern "C"
int WINAPI TimedEntryPoint(VOID)
{
    // We couldn't call LoadLibrary in DllMain,
    // so we detour SleepEx here...
    LONG error;

    TrueSleepEx = (DWORD (WINAPI *)(DWORD, BOOL))
        DetourFindFunction("kernel32.dll", "SleepEx");

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)TrueSleepEx, (void *)TimedSleepEx);
    error = DetourTransactionCommit();

    if (error == NO_ERROR) {
        printf("dslept" DETOURS_STRINGIFY(DETOURS_BITS) ".dll: "
               " Detoured SleepEx().\n");

    }
    else {
        printf("dslept" DETOURS_STRINGIFY(DETOURS_BITS) ".dll: "
               " Error detouring SleepEx(): %d\n", (int)error);
    }

    Verify("SleepEx", (PVOID)SleepEx);
    printf("\n");
    fflush(stdout);

    printf("dslept" DETOURS_STRINGIFY(DETOURS_BITS) ".dll: "
           " Calling EntryPoint\n");
    fflush(stdout);

    return TrueEntryPoint();
}

extern "C"
BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved)
{
    LONG error;
    (void)hinst;
    (void)reserved;

    if (DetourIsHelperProcess()) {
        return TRUE;
    }

    if (dwReason == DLL_PROCESS_ATTACH) {
        DetourRestoreAfterWith();

        printf("dslept" DETOURS_STRINGIFY(DETOURS_BITS) ".dll: "
               " Starting.\n");
        Verify("SleepEx", (PVOID)SleepEx);
        printf("\n");
        fflush(stdout);

        // NB: DllMain can't call LoadLibrary, so we hook the app entry point.
        TrueEntryPoint = (int (WINAPI *)(VOID))DetourGetEntryPoint(NULL);
        RawEntryPoint = TrueEntryPoint;

        Verify("EntryPoint", (PVOID)RawEntryPoint);

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)TrueEntryPoint, (void *)TimedEntryPoint);
        error = DetourTransactionCommit();

        Verify("EntryPoint after attach", (PVOID)RawEntryPoint);
        Verify("EntryPoint trampoline", (PVOID)TrueEntryPoint);

        if (error == NO_ERROR) {
            printf("dslept" DETOURS_STRINGIFY(DETOURS_BITS) ".dll: "
                   " Detoured EntryPoint().\n");
        }
        else {
            printf("dslept" DETOURS_STRINGIFY(DETOURS_BITS) ".dll: "
                   " Error detouring EntryPoint(): %d\n", (int)error);
        }
    }
    else if (dwReason == DLL_PROCESS_DETACH) {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        if (TrueSleepEx != NULL) {
            DetourDetach(&(PVOID&)TrueSleepEx, (void *)TimedSleepEx);
        }
        DetourDetach(&(PVOID&)TrueEntryPoint, (void *)TimedEntryPoint);
        error = DetourTransactionCommit();

        printf("dslept" DETOURS_STRINGIFY(DETOURS_BITS) ".dll: "
               " Removed Sleep() detours (%d), slept %d ticks.\n", (int)error, (int)dwSlept);

        fflush(stdout);
    }
    return TRUE;
}
//
///////////////////////////////////////////////////////////////// End of File.
