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

public class OpenSamlResponseDetector implements Detector{

    private static final String SAML_MISSING_RESP_SP = "SAML_MISSING_RESP_SP";
    private static final String SAML_MISSING_RESP_ID = "SAML_MISSING_RESP_ID";
    private static final String SAML_MISSING_RESP_ISSUER = "SAML_MISSING_RESP_ISSUER";
    private static final String SAML_MISSING_RESP_ASSERT = "SAML_MISSING_RESP_ASSERT";


    private static InvokeMatcherBuilder RESPONSE_CONSTRUCTOR = invokeInstruction().
            atClass("org.opensaml.saml.saml2.core.Response");
    private static InvokeMatcherBuilder RESPONSE_SP = invokeInstruction().
            atClass("org.opensaml.saml.saml2.core.Response").atMethod("setDestination");
    private static InvokeMatcherBuilder RESPONSE_ID = invokeInstruction().
            atClass("org.opensaml.saml.saml2.core.Response").atMethod("setID");
    private static InvokeMatcherBuilder RESPONSE_ISSUER = invokeInstruction().
            atClass("org.opensaml.saml.saml2.core.Response").atMethod("setIssuer");
    private static InvokeMatcherBuilder RESPONSE_ASSERTION = invokeInstruction().
            atClass("org.opensaml.saml.saml2.core.Response").atMethod("getAssertions");



    JavaClass javaClass;

    private BugReporter bugReporter;

    public OpenSamlResponseDetector(BugReporter bugReporter) {
        this.bugReporter = bugReporter;
    }

    @Override
    public void visitClassContext(ClassContext classContext) {

        boolean foundResponse = false; // must be true to trigger search for setID method
        boolean foundSetDestination = false;
        boolean foundSetID = false;
        boolean foundIssuer = false;
        boolean foundAssertion = false;
        boolean foundBuildKeyWord = false;
        javaClass = classContext.getJavaClass();
        Method[] methods = javaClass.getMethods();

        for (Method m : methods) {
            foundResponse = false;
            foundSetDestination = false;
            foundSetID = false;
            foundBuildKeyWord = false;
            foundAssertion = false;
            foundIssuer = false;

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
                if(RESPONSE_CONSTRUCTOR.matches(instruction, cpg)){
                    foundResponse = true;
                }
                if(RESPONSE_SP.matches(instruction, cpg)){
                    foundSetDestination = true;
                }
                if(RESPONSE_ID.matches(instruction, cpg)){
                    foundSetID = true;
                }
                if(RESPONSE_ISSUER.matches(instruction, cpg)){
                    foundIssuer = true;
                }
                if(RESPONSE_ASSERTION.matches(instruction, cpg)){
                    foundAssertion = true;
                }

            }


            if (foundResponse && foundBuildKeyWord && !foundSetDestination) {
                bugReporter.reportBug(new BugInstance(this, SAML_MISSING_RESP_SP, Priorities.HIGH_PRIORITY)
                        .addClassAndMethod(javaClass, m));
            }

            if (foundResponse && foundBuildKeyWord && !foundSetID){
                bugReporter.reportBug(new BugInstance(this, SAML_MISSING_RESP_ID, Priorities.HIGH_PRIORITY)
                        .addClassAndMethod(javaClass, m));
            }

            if (foundResponse && foundBuildKeyWord && !foundIssuer){
                bugReporter.reportBug(new BugInstance(this, SAML_MISSING_RESP_ISSUER, Priorities.HIGH_PRIORITY)
                        .addClassAndMethod(javaClass, m));
            }

            if (foundResponse && foundBuildKeyWord && !foundAssertion){
                bugReporter.reportBug(new BugInstance(this, SAML_MISSING_RESP_ASSERT, Priorities.HIGH_PRIORITY)
                        .addClassAndMethod(javaClass, m));
            }


        }



    }

    @Override
    public void report() {

    }
}




















