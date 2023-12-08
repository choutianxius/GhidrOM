//TODO write a description for this script
//@author 
//@category Examples
//@keybinding 
//@menupath 
//@toolbar 

// import ghidra.app.decompiler.DecompInterface;
// import ghidra.app.decompiler.DecompileResults;

// import ghidra.app.decompiler.PrettyPrinter;
// import ghidra.app.decompiler.ClangNode;

import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.util.FunctionSignatureFieldLocation;
import ghidra.program.model.mem.MemoryAccessException;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

import javax.swing.*;
import java.awt.*;
import java.util.ListIterator; 

import java.util.List;

import java.io.*;
import java.util.*;

public class stringAccessorJava extends GhidraScript {

    public void run() throws Exception {
        
		DecompInterface decompiler = new DecompInterface();
		decompiler.openProgram(currentProgram);
		Function currFn = getFunctionContaining(currentAddress);
		DecompileResults decompRs = decompiler.decompileFunction(currFn, 0, monitor);

		PrettyPrinter pp = new PrettyPrinter(currFn, decompRs.getCCodeMarkup(), null);
		String code = pp.print().getC();
        
		String instructions = new String();
        int instructIndex = 0;
        ArrayList<Instruction> instructArr = new ArrayList<Instruction>();
        ArrayList<String> accessVariables = new ArrayList<String>();
        ArrayList<String> accessIndexes = new ArrayList<String>();

        Iterator<ClangNode> markupIter = decompRs.getCCodeMarkup().iterator();

		while(markupIter.hasNext()){

            ClangNode obj = markupIter.next();

            if(obj.getMinAddress() != null && obj.getMaxAddress() != null){

                Iterator<AddressRange> addrSetIter = new AddressSet(obj.getMinAddress(), obj.getMaxAddress()).iterator();

                while (addrSetIter.hasNext()) {

                    AddressRange addrrange = addrSetIter.next();
                    Iterator<Address> addys = addrrange.iterator();

                    while(addys.hasNext()){

                        Instruction instruct = currentProgram.getListing().getInstructionAt(addys.next());
                        if(instruct == null){
                            continue;
                        }

                        instructions += instruct.toString() + "\n";
                        instructArr.add(instruct);
                        
                        String[] splitInstruct = instruct.toString().split(" ");
                        
                        if(splitInstruct[0].equals("CALL")){
                            
                            Address calledAddy = currentProgram.getAddressFactory().getAddress(splitInstruct[1]);
                            Function calledFunction = currentProgram.getListing().getFunctionAt(calledAddy);
                            String functionString = calledFunction.toString();
                            
                            if( functionString.contains("[]") ){

                                Instruction secondLastInstruct = instructArr.get(instructIndex - 2);
                                Instruction thirdLastInstruct = instructArr.get(instructIndex - 3);

                                String[] splitSecondLastInstruct = secondLastInstruct.toString().split(",");
                                String[] splitThirdLastInstruct = thirdLastInstruct.toString().split(",");
                                
                                println(secondLastInstruct.toString());
                                println(thirdLastInstruct.toString());
                                
                                if(splitSecondLastInstruct[1].substring(0,2).equals("0x")){
                                    accessIndexes.add(splitSecondLastInstruct[1].substring(2,splitSecondLastInstruct[1].length()));
                                }
                                else{
                                    accessIndexes.add("?");
                                }
                                accessVariables.add(splitThirdLastInstruct[1]);

                            }
                        }
                        instructIndex += 1;
                    }
                    // if(it.next() instanceof AddressRange){
                    //     println("Address spotted");
                    // }
			    }
            }
		}
        // println(instructions);
        int ind = code.indexOf("[]", 0);
        int targetnewline = code.indexOf("\n", ind);
        println("" + targetnewline);
        println(code);
        for(int i = 0;i<accessIndexes.size();i++){
            // code = code.replaceFirst("std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::size()", callingVariables.get(i));
            // Find more dynamic way of replacing entire line 
            String newCode = accessVariables.get(i) + "[" + accessIndexes.get(i) + "];";
            code = code.replaceFirst("std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::operator", newCode);
        }
        println(code);
    }

}
