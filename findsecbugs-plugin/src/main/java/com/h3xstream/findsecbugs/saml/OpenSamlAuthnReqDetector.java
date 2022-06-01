/**
 * Find Security Bugs
 * Copyright (c) Philippe Arteau, All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3.0 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.
 */

package com.h3xstream.findsecbugs.saml;

import com.h3xstream.findsecbugs.common.StackUtils;
import com.h3xstream.findsecbugs.common.matcher.InvokeMatcherBuilder;
import edu.umd.cs.findbugs.*;
import edu.umd.cs.findbugs.ba.ClassContext;
import edu.umd.cs.findbugs.ba.Hierarchy;
import edu.umd.cs.findbugs.ba.JavaClassAndMethod;
import org.apache.bcel.Const;
import org.apache.bcel.classfile.JavaClass;
import org.apache.bcel.classfile.Method;
import org.apache.bcel.generic.*;

import java.util.*;

import static com.h3xstream.findsecbugs.common.matcher.InstructionDSL.invokeInstruction;

public class OpenSamlAuthnReqDetector implements Detector {
    private static final String SAML_MISSING_AUTHN_ID = "SAML_MISSING_AUTHN_ID";
    private static final String SAML_MISSING_AUTHN_ISSUER = "SAML_MISSING_AUTHN_ISSUER";
    private static final String SAML_MISSING_AUTHN_BOTH = "SAML_MISSING_AUTHN_BOTH";

    private static InvokeMatcherBuilder AUTHN_REQ_CONSTRUCTOR = invokeInstruction().
            atClass("org.opensaml.saml.saml2.core.AuthnRequest");
    private static InvokeMatcherBuilder AUTHN_REQ_ID = invokeInstruction().
            atClass("org.opensaml.saml.saml2.core.AuthnRequest").atMethod("setID");
    private static InvokeMatcherBuilder AUTHN_REQ_ISSUER = invokeInstruction().
            atClass("org.opensaml.saml.saml2.core.AuthnRequest").atMethod("setIssuer");

    JavaClass javaClass;

    private BugReporter bugReporter;

    public OpenSamlAuthnReqDetector(BugReporter bugReporter) {
        this.bugReporter = bugReporter;
    }

    @Override
    public void visitClassContext(ClassContext classContext) {

        boolean foundAuthnRequest = false; // must be true to trigger search for setID method
        boolean foundSetID = false;
        boolean foundSetIssuer = false;
        boolean foundBuildKeyWord = false;
        javaClass = classContext.getJavaClass();
        Method[] methods = javaClass.getMethods();

        for (Method m : methods) {
            foundAuthnRequest = false;
            foundSetID = false;
            foundSetIssuer = false;
            foundBuildKeyWord = false;

            MethodGen methodGen = classContext.getMethodGen(m);
            ConstantPoolGen cpg = classContext.getConstantPoolGen();
            if (methodGen == null || methodGen.getInstructionList() == null) {
                continue; //No instruction .. nothing to do
            }

            if(methodGen.getName().toLowerCase().contains("build") ||
                    methodGen.getName().toLowerCase().contains("generate") ||
                    methodGen.getName().toLowerCase().contains("create") ||
                    methodGen.getName().toLowerCase().contains("construct")) {
                foundBuildKeyWord = true;
            }

            for (InstructionHandle instructionHandle : methodGen.getInstructionList()) {
                Instruction instruction = instructionHandle.getInstruction();
                if(!(instruction instanceof InvokeInstruction)) {
                    continue;
                }
                InvokeInstruction invokeInstruction = (InvokeInstruction) instruction;
                if(AUTHN_REQ_CONSTRUCTOR.matches(instruction, cpg)){
                    foundAuthnRequest = true;
                }
                if(AUTHN_REQ_ID.matches(instruction, cpg)){
                    foundSetID = true;
                }
                if(AUTHN_REQ_ISSUER.matches(instruction, cpg)){
                    foundSetIssuer = true;
                }

            }


            if (foundAuthnRequest && foundBuildKeyWord && !foundSetID && !foundSetIssuer) {
                bugReporter.reportBug(new BugInstance(this, SAML_MISSING_AUTHN_BOTH, Priorities.HIGH_PRIORITY)
                        .addClassAndMethod(javaClass, m));
            }

            if (foundAuthnRequest && foundBuildKeyWord && !foundSetID && foundSetIssuer){
                bugReporter.reportBug(new BugInstance(this, SAML_MISSING_AUTHN_ID, Priorities.HIGH_PRIORITY)
                        .addClassAndMethod(javaClass, m));
            }

            if (foundAuthnRequest && foundBuildKeyWord && foundSetID && !foundSetIssuer){
                bugReporter.reportBug(new BugInstance(this, SAML_MISSING_AUTHN_ISSUER, Priorities.HIGH_PRIORITY)
                        .addClassAndMethod(javaClass, m));
            }


        }



    }

    @Override
    public void report() {

    }



}
