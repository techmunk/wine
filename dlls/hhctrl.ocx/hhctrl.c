/*
 * hhctrl implementation
 *
 * Copyright 2004 Krzysztof Foltman
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include "wine/debug.h"

#define INIT_GUID
#include "hhctrl.h"

WINE_DEFAULT_DEBUG_CHANNEL(htmlhelp);

HINSTANCE hhctrl_hinstance;
BOOL hh_process;

BOOL WINAPI DllMain(HINSTANCE hInstance, DWORD fdwReason, LPVOID lpvReserved)
{
    TRACE("(%p,%d,%p)\n", hInstance, fdwReason, lpvReserved);

    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        hhctrl_hinstance = hInstance;
        DisableThreadLibraryCalls(hInstance);
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

static const char *command_to_string(UINT command)
{
#define X(x) case x: return #x
    switch (command)
    {
        X( HH_DISPLAY_TOPIC );
        X( HH_DISPLAY_TOC );
        X( HH_DISPLAY_INDEX );
        X( HH_DISPLAY_SEARCH );
        X( HH_SET_WIN_TYPE );
        X( HH_GET_WIN_TYPE );
        X( HH_GET_WIN_HANDLE );
        X( HH_ENUM_INFO_TYPE );
        X( HH_SET_INFO_TYPE );
        X( HH_SYNC );
        X( HH_RESERVED1 );
        X( HH_RESERVED2 );
        X( HH_RESERVED3 );
        X( HH_KEYWORD_LOOKUP );
        X( HH_DISPLAY_TEXT_POPUP );
        X( HH_HELP_CONTEXT );
        X( HH_TP_HELP_CONTEXTMENU );
        X( HH_TP_HELP_WM_HELP );
        X( HH_CLOSE_ALL );
        X( HH_ALINK_LOOKUP );
        X( HH_GET_LAST_ERROR );
        X( HH_ENUM_CATEGORY );
        X( HH_ENUM_CATEGORY_IT );
        X( HH_RESET_IT_FILTER );
        X( HH_SET_INCLUSIVE_FILTER );
        X( HH_SET_EXCLUSIVE_FILTER );
        X( HH_INITIALIZE );
        X( HH_UNINITIALIZE );
        X( HH_PRETRANSLATEMESSAGE );
        X( HH_SET_GLOBAL_PROPERTY );
    default: return "???";
    }
#undef X
}

HWND WINAPI HtmlHelpW(HWND caller, LPCWSTR filename, UINT command, DWORD data)
{

    TRACE("(%p, %s, command=%s, data=%d)\n",
          caller, debugstr_w( filename ),
          command_to_string( command ), data);

    switch (command)
    {
    case HH_DISPLAY_TOPIC:
    case HH_DISPLAY_TOC:
    case HH_DISPLAY_SEARCH:
    case HH_HELP_CONTEXT: {
        HHInfo *info;
        BOOL res;

        FIXME("Not all HH cases handled correctly\n");

        info = CreateHelpViewer(filename);

        res = NavigateToChm(info, info->pCHMInfo->szFile, info->WinType.pszFile);
        if(!res)
            ReleaseHelpViewer(info);

        return NULL; /* FIXME */
    }
    default:
        FIXME("HH case %s not handled.\n", command_to_string( command ));
    }

    return 0;
}

HWND WINAPI HtmlHelpA(HWND caller, LPCSTR filename, UINT command, DWORD data)
{
    WCHAR *wfile = NULL;
    HWND result;

    if (filename)
    {
        DWORD len = MultiByteToWideChar( CP_ACP, 0, filename, -1, NULL, 0 );

        wfile = hhctrl_alloc(len*sizeof(WCHAR));
        MultiByteToWideChar( CP_ACP, 0, filename, -1, wfile, len );
    }

    result = HtmlHelpW( caller, wfile, command, data );

    hhctrl_free(wfile);
    return result;
}

/******************************************************************
 *		doWinMain (hhctrl.ocx.13)
 */
int WINAPI doWinMain(HINSTANCE hInstance, LPSTR szCmdLine)
{
    MSG msg;

    hh_process = TRUE;

    /* FIXME: Check szCmdLine for bad arguments */
    HtmlHelpA(GetDesktopWindow(), szCmdLine, HH_DISPLAY_TOPIC, 0);

    while (GetMessageW(&msg, 0, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    return 0;
}

/******************************************************************
 *		DllGetClassObject (hhctrl.ocx.@)
 */
HRESULT WINAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID *ppv)
{
    FIXME("(%s %s %p)\n", debugstr_guid(rclsid), debugstr_guid(riid), ppv);
    return CLASS_E_CLASSNOTAVAILABLE;
}
