/*
 * (C) Copyright 2006 VeriSign, Inc.
 * Developed by Sxip Identity
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
%include "exception.i"
%{
#include "Exceptions.h"
    %}

//%include "src/Exceptions.h"

class DsigException
{
public:
    DsigException ();
    const char* what() const;
};

#if defined(SWIGPYTHON)
%extend DsigException {
    char* __str__ ()
    {
        return (char*)self->what();
    }
}
#endif

// Generic exceptions (with Swig analogs, see typemaps below)
class IOError:     public DsigException {};
class MemoryError: public DsigException {};
class ValueError:  public DsigException {};

// Exception classes specific to DSIG
class XMLError:    public DsigException {};
class KeyError:    public DsigException {};
class DocError:    public DsigException {};
class XPathError:  public DsigException {};
class TrustVerificationError:  public DsigException {};
class LibError:    public DsigException 
{
public:
    static void clearErrorLogs ();
};

// Fallthrough exception handler
%exception { 
    try 
    { 
        $action 
    } 
    catch (DsigException& e) 
    { 
        SWIG_exception(SWIG_RuntimeError, e.what()); 
    }
 }

%typemap(throws) IOError %{
    SWIG_exception(SWIG_IOError, $1.what());
    %}

%typemap(throws) MemoryError %{
    SWIG_exception(SWIG_MemoryError, $1.what());
    %}

%typemap(throws) ValueError %{
    SWIG_exception(SWIG_ValueError, $1.what());
    %}
