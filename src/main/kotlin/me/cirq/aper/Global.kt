package me.cirq.aper

import soot.Scene
import soot.SootClass


val CHECK_APIS = setOf(
        // all implemented CHECK apis
        "<android.support.v4.content.ContextCompat: int checkSelfPermission(android.content.Context,java.lang.String)>",
        "<androidx.core.content.ContextCompat: int checkSelfPermission(android.content.Context,java.lang.String)>",

        // not supported for backward-compatibility
        "<android.content.ContextWrapper: int checkSelfPermission(java.lang.String)>",
        "<android.content.Context: int checkSelfPermission(java.lang.String)>",

        // legacy api
        "<android.support.v4.content.PermissionChecker: int checkSelfPermission(android.content.Context,java.lang.String)>",
        "<androidx.code.content.PermissionChecker: int checkSelfPermission(android.content.Context,java.lang.String)>"
)
const val ABS_CHECK = "<android.content.Context: int checkSelfPermission(java.lang.String)>"
const val ALTER_CHECK = "<android.content.ContextWrapper: int checkSelfPermission(java.lang.String)>"


val REQUEST_APIS: Set<String> = setOf(
        // implemented REQUEST apis for activity
        "<android.app.Activity: void requestPermissions(java.lang.String[],int)>",
        "<android.support.v4.app.ActivityCompat: void requestPermissions(android.app.Activity,java.lang.String[],int)>",
        "<androidx.core.app.ActivityCompat: void requestPermissions(android.app.Activity,java.lang.String[],int)>",

        // implemented REQUEST apis for fragment
        "<android.support.v4.app.Fragment: void requestPermissions(java.lang.String[],int)>",   // before androidx
        "<androidx.fragment.app.Fragment: void requestPermissions(java.lang.String[],int)>",    // androidx migrations for previous
        // the later two are not recommanded
        "<android.app.Fragment: void requestPermissions(java.lang.String[],int)>",              // deprecatd
        "<android.support.v13.app.FragmentCompat: void requestPermissions(android.app.Fragment,java.lang.String[],int)>"    // no appear in androidx
)


// a subsignature: https://stackoverflow.com/questions/38615509/
const val HANDLE_API = "void onRequestPermissionsResult(int,java.lang.String[],int[])"


val PERMISSION_MAINTAINING_APIS = CHECK_APIS + REQUEST_APIS + HANDLE_API

val PERMISSION_MAINTAINING_API_NAMES = setOf("checkSelfPermission", "requestPermissions", "onRequestPermissionsResult")


const val SDK_INT_FIELD = "<android.os.Build\$VERSION: int SDK_INT>"

val RUNNABLE_CLASS: SootClass = Scene.v().getSootClass("java.lang.Runnable")
