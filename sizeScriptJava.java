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

public class sizeScriptJava extends GhidraScript {

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
        ArrayList<String> callingVariables = new ArrayList<String>();

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
                            
                            if( functionString.contains("size") ){

                                Instruction prevInstruct = instructArr.get(instructIndex - 2);
                                String[] splitPrevInstruct = prevInstruct.toString().split(",");
                                String variable = splitPrevInstruct[1];
                                callingVariables.add(variable);

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
        print(code);
        for(int i = 0;i<callingVariables.size();i++){
            println(callingVariables.get(i));
            code = code.replaceFirst("std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::size()", callingVariables.get(i));
        }
        println(code);
    }

}
