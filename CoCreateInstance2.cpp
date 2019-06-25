#include "guid.h"
#include <iostream>
#include <windows.h>
#include <netfw.h>
#include <objbase.h>
#include <oleauto.h>
#include <stdio.h>
#include "SimpleAssert.h"


HRESULT WINAPI DECLSPEC_HOTPATCH CoCreateInstance(
 Guid rclsid,
LPUNKNOWN pUnkOuter,
DWORD dwClsContext,
Guid iid,
LPVOID *ppv)
{
MULTI_QI multi_qi = { iid };
HRESULT hres;

TRACE("(rclsid=%s, pUnkOuter=%p, dwClsContext=%08x, riid=%s, ppv=%p)\n", debugstr_guid(rclsid),
           pUnkOuter, dwClsContext, debugstr_guid(iid), ppv);

     if (ppv==0)
         return E_POINTER;

     hres = CoCreateInstanceEx(rclsid, pUnkOuter, dwClsContext, NULL, 1, &multi_qi);
     *ppv = multi_qi.pItf;
    return hres;
 }
