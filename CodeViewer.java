/* ###
 * IP: GHIDRA
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
//Writes "Hello World" in a popup dialog.
//@category Examples

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
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
import java.util.Iterator;

public class CodeViewer extends GhidraScript {
	
	private DecompInterface decompiler;

    @Override
    public void run() throws Exception {
        SwingUtilities.invokeLater(() -> {
            GhidraAppFrame frame = new GhidraAppFrame();
            frame.setVisible(true);
        });
    }

    private class GhidraAppFrame extends JFrame {
        private JTextArea assemblyTextArea;
        private JTextArea decompiledTextArea;

        GhidraAppFrame() {
            super("Ghidra Code Viewer");
            setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
            setSize(800, 600);

            JPanel panel = new JPanel(new BorderLayout());
            add(panel);

            assemblyTextArea = new JTextArea();
            decompiledTextArea = new JTextArea();

            JScrollPane assemblyScrollPane = new JScrollPane(assemblyTextArea);
            JScrollPane decompiledScrollPane = new JScrollPane(decompiledTextArea);

            JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, assemblyScrollPane, decompiledScrollPane);
            splitPane.setResizeWeight(0.5);

            panel.add(splitPane, BorderLayout.CENTER);

            loadCode();
        }

        private void loadCode() {
            // Replace with the function you are interested in
            Function function = getFunction("main");

            if (function != null) {
                //loadAssemblyCode(function);
            	loadUnmodifiedDecompiledCode(function);
                loadDecompiledCode(function);
            }
        }

        private Function getFunction(String functionName) {
            FunctionIterator functionIterator = currentProgram.getListing().getFunctions(true);
            while (functionIterator.hasNext()) {
                Function function = functionIterator.next();
                if (function.getName().equals(functionName)) {
                    return function;
                }
            }
            return null;
        }

        private void loadAssemblyCode(Function function) {
            StringBuilder assemblyCode = new StringBuilder();
            Listing listing = currentProgram.getListing();

            // Iterate through all instructions in the program
            for (Instruction instruction : listing.getInstructions(function.getBody(), true)) {
                // Get the address of the instruction
                Address address = instruction.getAddress();
                
                // Append the assembly code followed by a new line
                assemblyCode.append(instruction.toString()).append("\n");
            }

            assemblyTextArea.setText(assemblyCode.toString());
        }
        
        private void loadUnmodifiedDecompiledCode(Function function) {
        	StringBuilder decompiledCode = new StringBuilder();
            
            // Create a DecompInterface
            try {
            	DecompInterface decompiler = new DecompInterface();
                decompiler.openProgram(currentProgram);

                // Perform decompilation
                DecompileResults decompileResults = decompiler.decompileFunction(function, 0, monitor);

                // Get the decompiled code as a string
                String decompiledFunction = decompileResults.getDecompiledFunction().getC();
                decompiledCode.append(decompiledFunction);
            } catch (Exception e) {
                e.printStackTrace();
                decompiledCode.append("Error decompiling function: ").append(e.getMessage());
            } finally {
                // Close DecompInterface in finally block to ensure it's closed even if an exception occurs
                if (decompiler != null) {
                    decompiler.dispose();
                }
            }
            
            assemblyTextArea.setText(decompiledCode.toString());
        }

        private void loadDecompiledCode(Function function) {
            StringBuilder decompiledCode = new StringBuilder();
            
            // Create a DecompInterface
            try {
            	DecompInterface decompiler = new DecompInterface();
                decompiler.openProgram(currentProgram);

                // Perform decompilation
                DecompileResults decompileResults = decompiler.decompileFunction(function, 0, monitor);

                // Get the decompiled code as a string
                String decompiledFunction = decompileResults.getDecompiledFunction().getC();
                decompiledCode.append(decompiledFunction);
            } catch (Exception e) {
                e.printStackTrace();
                decompiledCode.append("Error decompiling function: ").append(e.getMessage());
            } finally {
                // Close DecompInterface in finally block to ensure it's closed even if an exception occurs
                if (decompiler != null) {
                    decompiler.dispose();
                }
            }
            
            // std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::operator+=
            
            // Search for the specified string in the decompiled code
            String searchString = "std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::operator+=";
            String foundString = "";
            boolean searchStringFound = false;
            String[] lines = decompiledCode.toString().split(";"); // Split by newlines

            for (String line : lines) {
                if (line.contains(searchString)) {
                	popup(line);
                    searchStringFound = true;
                    foundString = line;
                    String newString = formatParameters(foundString + ";");
                    decompiledCode = new StringBuilder(decompiledCode.toString().replaceAll(Pattern.quote(line), Matcher.quoteReplacement("\n" + "  " + newString)));
                    popup(newString);
                    //break;
                }
            }

            if (searchStringFound) {
            	// Format the two parameters if the string is found
                popup("String found in decompiled code!");
            } else {
                popup("String not found in decompiled code.");
            }

            decompiledTextArea.setText(decompiledCode.toString());
        }
        
        private String formatParameters(String originalCode) {
            // Find the index of '(' in the original code
            int openingParenIndex = originalCode.indexOf('(');

            if (openingParenIndex != -1) {
                // Find the index of ',' and ')' after '('
                int commaIndex = originalCode.indexOf(',', openingParenIndex);
                int semicolonIndex = originalCode.indexOf(';', openingParenIndex);

                if (commaIndex != -1 && semicolonIndex != -1) {
                    // Extract substrings for first and second parameters
                    String firstParam = originalCode.substring(openingParenIndex + 1, commaIndex).trim();
                    String secondParam = originalCode.substring(commaIndex + 1, semicolonIndex - 1).trim();

                    // Return the formatted string
                    return firstParam + " += " + secondParam;
                }
            }

            // If the pattern is not found or extraction fails, return the original code
            return originalCode;
        }
    }
}
