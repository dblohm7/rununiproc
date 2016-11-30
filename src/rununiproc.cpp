/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <iostream>
#include <memory>
#include <sstream>
#include <type_traits>

#include <windows.h>

#include <intrin.h>
#if defined(_M_X64)
#pragma intrinsic(_BitScanForward64)
#define CPU_BITSCANFORWARD _BitScanForward64
#else
#pragma intrinsic(_BitScanForward)
#define CPU_BITSCANFORWARD _BitScanForward
#endif

#if !defined(UNICODE) || !defined(_UNICODE)
#error Define UNICODE and _UNICODE please
#endif
#if _WIN32_WINNT < 0x0600
#error _WIN32_WINNT should be set for Windows Vista
#endif

struct HandleDeleter
{
  void operator()(HANDLE aHandle)
  {
    if (aHandle) {
      ::CloseHandle(aHandle);
    }
  }
};

struct ProcThreadAttrListDeleter
{
  void operator()(LPPROC_THREAD_ATTRIBUTE_LIST aAttrList)
  {
    ::DeleteProcThreadAttributeList(aAttrList);
    delete[] reinterpret_cast<char*>(aAttrList);
  }
};

using UniqueHandle = std::unique_ptr<std::remove_pointer<HANDLE>::type,
                                     HandleDeleter>;

using ProcThreadAttributeListPtr = std::unique_ptr<
  std::remove_pointer<LPPROC_THREAD_ATTRIBUTE_LIST>::type,
  ProcThreadAttrListDeleter>;

int
wmain(int argc, wchar_t* argv[])
{
  if (argc < 2) {
    std::wcerr << L"At least one argument required." << std::endl;
    return 1;
  }

  DWORD const exePathBufLen = 32767;
  auto exePathBuf = std::make_unique<wchar_t[]>(exePathBufLen);
  if (!exePathBuf) {
    std::wcerr << L"Failed to allocate exePathBuf." << std::endl;
    return 1;
  }

  // For now we only support searching for exe files
  DWORD pathLen = SearchPath(nullptr, argv[1], L".exe", exePathBufLen,
                             exePathBuf.get(), nullptr);
  if (!pathLen) {
    DWORD err = GetLastError();
    std::wcerr << L"SearchPath failed with error code " << err << std::endl;
    return 1;
  }
  if (pathLen >= exePathBufLen) {
    std::wcerr << L"SearchPath failed: path too long." << std::endl;
    return 1;
  }

#if defined(DEBUG)
  std::wcout << L"Launching \"" << exePathBuf.get() << L"\"" << std::endl;
#endif

  UniqueHandle job(CreateJobObject(nullptr, nullptr));
  if (!job) {
    std::wcerr << L"CreateJobObject failed." << std::endl;
    return 1;
  }

  DWORD_PTR processAffinityMask;
  DWORD_PTR systemAffinityMask;
  if (!GetProcessAffinityMask(GetCurrentProcess(), &processAffinityMask,
                              &systemAffinityMask)) {
    std::wcerr << L"Unable to obtain our CPU affinity mask." << std::endl;
    return 1;
  }

  // Scan the process affinity mask for the first available CPU
  unsigned long index;
  if (!CPU_BITSCANFORWARD(&index, processAffinityMask)) {
    std::cerr << "CPU affinity mask is zero?!" << std::endl;
    return 1;
  }

  JOBOBJECT_BASIC_LIMIT_INFORMATION basicLimitInfo = {};
  basicLimitInfo.LimitFlags = JOB_OBJECT_LIMIT_AFFINITY;
  basicLimitInfo.Affinity = (1 << index);

  if (!SetInformationJobObject(job.get(), JobObjectBasicLimitInformation,
                               &basicLimitInfo, sizeof(basicLimitInfo))) {
    std::wcerr << L"Unable to set basic limit information on job object."
               << std::endl;
    return 1;
  }

  SIZE_T attrListSize = 0;
  if (!InitializeProcThreadAttributeList(nullptr, 1, 0, &attrListSize) &&
      GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
    std::wcerr << L"InitializeProcThreadAttributeList for sizing failed"
               << std::endl;
    return 1;
  }

  ProcThreadAttributeListPtr
    attrList(reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(new char[attrListSize]));
  if (!attrList) {
    std::wcerr << L"Could not allocate proc thread attribute list of size "
               << attrListSize << std::endl;
    return 1;
  }

  if (!InitializeProcThreadAttributeList(attrList.get(), 1, 0, &attrListSize)) {
    std::wcerr << L"InitializeProcThreadAttributeList failed"
               << std::endl;
    return 1;
  }

  HANDLE inheritableHandleWhitelist[] = {
    GetStdHandle(STD_INPUT_HANDLE),
    GetStdHandle(STD_OUTPUT_HANDLE),
    GetStdHandle(STD_ERROR_HANDLE)
  };

  if (!UpdateProcThreadAttribute(attrList.get(), 0,
                                 PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                 inheritableHandleWhitelist,
                                 sizeof(inheritableHandleWhitelist), nullptr,
                                 nullptr)) {
    std::wcerr << L"UpdateProcThreadAttribute failed" << std::endl;
    return 1;
  }

  std::wostringstream oss;
  oss << L"\"" << exePathBuf.get() << L"\"";
  if (argc > 2) {
    oss << L" ";
  }

  for (int i = 2; i < argc; ++i) {
    oss << L"\"" << argv[i] << L"\"";
    if (i != argc - 1) {
      oss << L" ";
    }
  }

  std::wstring cmdLine(oss.str());
  if (cmdLine.size() > exePathBufLen) {
    std::wcerr << L"Command line is too long for CreateProcess" << std::endl;
    return 1;
  }

  STARTUPINFOEX siex{};
  siex.StartupInfo.cb = sizeof(siex);
  siex.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
  siex.StartupInfo.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
  siex.StartupInfo.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
  siex.StartupInfo.hStdError = GetStdHandle(STD_ERROR_HANDLE);
  siex.lpAttributeList = attrList.get();

  PROCESS_INFORMATION pi;
  if (!CreateProcess(exePathBuf.get(), const_cast<wchar_t*>(cmdLine.c_str()),
                     nullptr, nullptr, TRUE, CREATE_SUSPENDED |
                     CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
                     nullptr, nullptr, &siex.StartupInfo, &pi)) {
    DWORD err = GetLastError();
    std::wcerr << L"CreateProcess failed with error code " << err << std::endl;
    return 1;
  }

  UniqueHandle childProcess(pi.hProcess);
  UniqueHandle childMainThread(pi.hThread);

  if (!AssignProcessToJobObject(job.get(), childProcess.get())) {
    DWORD err = GetLastError();
    std::wcerr << L"AssignProcessToJobObject failed with error code " << err
               << std::endl;
    TerminateProcess(childProcess.get(), 1);
    return 1;
  }

  if (ResumeThread(childMainThread.get()) == ((DWORD)-1)) {
    DWORD err = GetLastError();
    std::wcerr << L"ResumeThread failed with error code " << err << std::endl;
    TerminateProcess(childProcess.get(), 1);
    return 1;
  }

  if (WaitForSingleObject(childProcess.get(), INFINITE) != WAIT_OBJECT_0) {
    DWORD err = GetLastError();
    std::wcerr << L"WaitForSingleObject failed with error code " << err
               << std::endl;
    // Not returning 1 here since technically the process started successfully
    return 0;
  }

  // We'll forward the child process's return code. By default the code will
  // be 0; even if GetExitCodeProcess() failed, technically we still did start
  // the child process successfully.
  DWORD exitCode = 0;
  if (!GetExitCodeProcess(childProcess.get(), &exitCode)) {
    DWORD err = GetLastError();
    std::wcerr << L"GetExitCodeProcess failed with error code " << err
               << std::endl;
  }

  return static_cast<int>(exitCode);
}

