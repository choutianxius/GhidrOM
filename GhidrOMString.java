//Analyze the current function and reveal the object for method calls (Object Mapping)
//Implemented 4 methods of the string class in the standard library
//@author Brian Nguyen, Maria Matamoros, Tianxiu Zhou and Vyom Gupta from 23 Fall CSCE451 @ TAMU
import ghidra.app.script.GhidraScript;

import javax.swing.*;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Toolkit;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.ClangNode;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.ClangCommentToken;
import ghidra.app.decompiler.ClangBreak;
import ghidra.app.decompiler.ClangCommentToken;
import ghidra.app.decompiler.ClangFuncNameToken;
import ghidra.app.decompiler.ClangStatement;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;

public class GhidrOMString extends GhidraScript {

  private int ARGUMENT_ASM_WINDOW_SIZE = 10;

  @Override
  public void run() throws Exception {
    this.println("Welcome to GhidrOM: Ghidra Object Mapping!");
    this.println("Currently implemented for 4 methods of the string class");

    DecompInterface decompiler = new DecompInterface();
    decompiler.openProgram(this.currentProgram);
    Function currFunc = this.getFunctionContaining(this.currentAddress);
    DecompileResults rs = decompiler.decompileFunction(currFunc, 0, this.monitor);
    ClangTokenGroup tokgroup = rs.getCCodeMarkup();

    /*
     * Loop throught the decompile results to find the target C code
     * <code>tokgroup</code> is a tree containing <code>ClangNode</code>s,
     * whose structure may vary depending on the decompiled program.
     * The most problematic fact is that the tree's depth is not fixed, making
     * it hard to traverse it using nested loops.
     * To address this issue, the <code>flatten</code> method of the ClangTokenGroup
     * can be used to turn the ClangNode tree into an array of its leaves in order
     * (Try refresh your memory about DSA)
     * Alternatively, you may write a recursive function to do the job
     */
    List<ClangNode> flattened = new ArrayList<>();
    tokgroup.flatten(flattened);

    StringBuilder revisedCCode = new StringBuilder();
    StringBuilder line = new StringBuilder(); // temporarily stores the current line
    String beautifiedLine = null;


    // start looping
    for (ClangNode node : flattened) {
      String token = node.toString();
      if ((token.isEmpty()) && (node.getClass() != ClangBreak.class)) continue; // skip empty tokens
      if (node.getClass() == ClangCommentToken.class) continue; // skip ghidra added comments
      if (node.getClass() == ClangBreak.class) { // hit line breaks, add the current line and indentation
        if (node.Parent().getClass() == ClangStatement.class) continue; // skip unnecessary line breaks within statements
        if (!line.toString().isBlank()) { // add the current line only when it's not blank
          if (beautifiedLine != null) {
            revisedCCode.append(beautifiedLine);
            if (beautifiedLine.contains("[RAX]")) {
              revisedCCode.append(" // [RAX] is probably the return value of the previous CALL");
            }
          } else {
            revisedCCode.append(line.toString());
          }
          revisedCCode.append("\n");
        }
        line.setLength(0); // clear the line
        beautifiedLine = null; // clear the beautified line

        int indentSize = ((ClangBreak) node).getIndent();
        line.append(new String(new char[indentSize]).replace("\0", " "));
        continue;
      }
      if (node.getClass() != ClangFuncNameToken.class) { // tokens that we are not interested in
        line.append(node.toString());
        continue;
      }

      int fnCallType = this.determineTargetEntity(token);

      if (fnCallType < 0) { // function calls that we are not interested in
        line.append(node.toString());
        continue;
      }

      /*
       * Now we've found a token representing a method call that we're interested.
       * First, the previous up to <code>ARGUMENT_ASM_WINDOW_SIZE</code> assembly instructions
       * from the current CALL instruction are found
       * Then, the arguments of the method call are identified using <code>findArgs</code>
       * Finally, using the type of the method call, and the found arguments, the beautified C
       * code is made from the original line
       */
      List<String> asm = new ArrayList<>();
      Instruction baseInstr = this.getInstructionAt(node.getMinAddress());
      asm.add(baseInstr.toString());
      Instruction instr = baseInstr;
      for (int ii=0; ii<this.ARGUMENT_ASM_WINDOW_SIZE-1; ii++) {
        instr = instr.getPrevious();
        if (instr == null) break;
        if (instr.toString().startsWith("CALL")) break;
        asm.add(0, instr.toString());
      }

      List<String> args = this.findArgs(asm);
      if (args.size() == 0) {
        this.println("Got instructions but no args found");
        for (String asmLine : asm) this.println(asmLine);
        line.append(token);
        continue;
      }

      beautifiedLine = this.beautifyStatement(args, fnCallType, line);

    }
    revisedCCode.append(line.toString()); // do not forget the last line


    /*
     * Display the output in a new window
     */
    JFrame frame = new JFrame("GhidrOM");

    JTextArea textArea = new JTextArea(revisedCCode.toString());
    textArea.setEditable(false);
    textArea.setLineWrap(true);
    textArea.setWrapStyleWord(true);

    JPanel mainPanel = new JPanel(new BorderLayout());
    mainPanel.add(new JScrollPane(textArea));
    frame.getContentPane().add(mainPanel);

    Dimension screenSize = Toolkit.getDefaultToolkit().getScreenSize();
    int width = (int) (screenSize.getWidth() * 0.5);
    int height = (int) (screenSize.getHeight() * 0.75);
    int x = (int) ((screenSize.getWidth() - width) / 2); // center horizontally
    int y = (int) ((screenSize.getHeight() - height) / 2); // center vertically
    frame.setLocation(x, y);
    frame.setSize(width, height);
    frame.setVisible(true);

    decompiler.dispose();
    this.println("Analysis completed!");
  }



  /**
   * Determine the type of the input statement part. Return a number representing the target method, if the statement part represents it.
   * @param token
   * @return -1 if irrelevant, 0 if string constructor, 1 if string <code>size</code>, 2 if string accessor, 3 if string +=
   */
  private int determineTargetEntity(String token) {
    if (token.equals("basic_string") || token.equals("basic_string<std::allocator<char>>")) {
      return 0; // string constructor
    } else if (token.equals("size")) {
      return 1; // string size
    } else if (token.equals("operator+=")) {
      return 2;
    } else if (token.equals("operator[]")) {
      return 3;
    }

    return -1;
  }



  /**
   * Find the arguments passed to the function from the asm code, like local_a8.
   * <p>
   * For a local variable, the number in the object name after "_" is calculated using the offset from RBP. For example, local_a8 correspondes to [RBP - 0xa0].
   * <p>
   * For a non-local variable, the original form from the asm code is used.
   * <p>
   * Support up to 6 arguments: RDI, RSI, RDX, RCX, R8, R9
   * @param asm List of instructions in forward order.
   * @return The list of variable names.
   */
  private List<String> findArgs(List<String> asm) {
    /*
     * Sample ASM
     * 
     * LEA RDX,[RBP + -0xc1]
     * LEA RAX,[RBP + -0xc0]
     * LEA RCX,[0x10300c]
     * MOV RSI,RCX
     * MOV RDI,RAX
     * CALL 0x00102a14
     */
    List<String> args = new ArrayList<>();
    String[] validRegs = {"RDI", "RSI", "RDX", "RCX", "R8", "R9"};
    for (String reg : validRegs) {
      String arg = this.findArgInReg(asm, reg);
      if (arg == null) {
        return args;
      }
      args.add(arg);
    }
    return args;
  }



  /**
   * Given the asm instructions, find the argument that is finally placed in the given register before calling the method.
   * @param asm List of instructions in forward order
   * @param reg Register name: RDI, RSI, RDX, RCX, R8, or R9
   * @return Variable name.
   */
  private String findArgInReg(List<String> asm, String reg) {
    /*
     * Sample ASM
     *
     * LEA RDX,[RBP + -0xc1]
     * LEA RAX,[RBP + -0xc0]
     * LEA RCX,[0x10300c]
     * MOV RSI,RCX
     * MOV RDI,RAX
     * CALL 0x00102a14
     *
     * Note that sometimes there are different data sizes for MOVxx
     *
     * MOV EAX,dword ptr [RBP + local_ac]
     * MOVSXD RDX,EAX
     * LEA RAX,[RBP + -0x80]
     * MOV RSI,RDX
     * MOV RDI,RAX
     *
     * MOVZX EAX,byte ptr [RAX]
     * MOVSX EDX,AL
     * LEA RAX,[RBP + -0x60]
     * MOV ESI,EDX
     * MOV RDI,RAX
     */

    /**
     * Whether the register contains an argument, or is it just used to hold intermediate values?
     */
    boolean isArg = false;
    String inReg = converToFullWidthReg(reg);
    String line;

    for (int i=asm.size()-1; i>=0; i--) {
      line = asm.get(i);
      if (line.startsWith("CALL")) continue;
      if (!line.contains(",")) continue;
      // parse asm line: <operator> <leftOperand>,<rightOperand>
      int leftOperandStartIdx = line.indexOf(" ", 0) + 1;
      int operatorEndIdx = leftOperandStartIdx - 1;
      int rightOperandStartIdx = line.indexOf(",", 0) + 1;
      int leftOperandEndIdx = rightOperandStartIdx - 1;
      String operator = line.substring(0, operatorEndIdx);
      String leftOperand = converToFullWidthReg(line.substring(leftOperandStartIdx, leftOperandEndIdx));
      String rightOperand = converToFullWidthReg(line.substring(rightOperandStartIdx));
      if (rightOperand.contains("[")){ // adjust for ptr size
        int rightOperandStartIdx1 = rightOperand.indexOf("[");
        rightOperand = converToFullWidthReg(rightOperand.substring(rightOperandStartIdx1));
      } 

      if (rightOperand.equals(reg) && (!isArg)) { // Assumption: Once an argument is placed in a register, that register will not be changed until the call
        return null;
      }
      if (leftOperand.equals(reg) && (!isArg)) {
        isArg = true;
      }
      if (leftOperand.equals(inReg)) {
        if (operator.equals("LEA")) {
          return this.convertToVarName(rightOperand);
        } else if (operator.startsWith("MOV")) {
          if (rightOperand.startsWith("[")) {
            return this.convertToVarName(rightOperand);
          }
          inReg = rightOperand; // MOV RDI,RAX
        }
      }
    }
    return null;
  }



  /**
   * Convert a variable name in asm to a C name. e.g.:
   * <p>
   * Local variables: <code>[RBP + -0x80]</code> => <code>local_88</code>
   * <p>
   * Global variables: <code>[0x1234]</code> => <code>[0x1234]</code>
   * @param rightOperand
   * @return <code>[absolute address]</code> for global variables, <code>local_(offset+8)</code> for local variables
   */
  private String convertToVarName(String rightOperand) {
    // 1. right operand is not [RBP + -0xc0] ([0x10300c]) => return "[0x10300c]""
    if (!rightOperand.substring(1, 4).equals("RBP")) {
      return rightOperand;
    }
    // 2. right operand is [RBP + -0xc0] => return "local_c8"
    String offsetString = rightOperand.substring(7, rightOperand.length()-1);
    if (!offsetString.startsWith("-0x")) {
      return rightOperand;
    }
    int numberAfterUnderscore = Integer.parseInt(offsetString.substring(3), 16) + 0x8;
    return "local_" + Integer.toHexString(numberAfterUnderscore);
  }



  /**
   * Convert a register name to the full width (64 bit) version
   * @param reg Original register name, in upper case
   * @return Full width version of the register, or the original name for non-regs. e.g., AL => RAX, EDI => RDI, EDX => RDX, [RBP + -0xc0] => [RBP + -0xc0]
   */
  private String converToFullWidthReg(String reg) {
    if (reg.contains("[")) return reg;
    if (reg.contains("A")) return "RAX";
    if (reg.contains("B")) return "RBX";
    if (reg.contains("C")) return "RCX";
    if (reg.contains("DI")) return "RDI";
    if (reg.contains("D")) return "RDX";
    if (reg.contains("S")) return "RSI";
    return reg;
  }



  /**
   * Make the beautified C statement line from the arguments and the method type
   * @param args Arguments, in forward order
   * @param type Indicator of the method type
   * @return Beautified C statement line
   */
  private String beautifyStatement(List<String> args, int type, StringBuilder line) {
    String prevLine = line.toString();
    StringBuilder alteredLine = new StringBuilder(
        prevLine.replaceAll(
          "std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::", ""));

    if (type == 0) {
      if (args.size() < 1) return null;

      alteredLine.append(args.get(0));
      alteredLine.append(" = std::string(");
      for (int ai=1; ai<args.size(); ai++) {
        alteredLine.append(args.get(ai));
        if (ai<args.size()-1) {
          alteredLine.append(",");
        }
      }
      alteredLine.append(");");
      return alteredLine.toString();
    }

    //     uVar2 = std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::
    else if (type == 1) { // xxxsize(string_var, ...other_vars)
      if (args.size() < 1) return null;
      
      alteredLine.append(args.get(0));
      alteredLine.append(".size(");
      for (int ai=1; ai<args.size(); ai++) {
        alteredLine.append(args.get(ai));
        if (ai<args.size()-1) {
          alteredLine.append(",");
        }
      }
      alteredLine.append(");");
      return alteredLine.toString();
    }

    else if (type == 2) { // +=
      if (args.size() < 2) return null;

      alteredLine.append(args.get(0));
      alteredLine.append(" += ");
      alteredLine.append(args.get(1));
      alteredLine.append(";");
      return alteredLine.toString();
    }

    else if (type == 3) {
      if (args.size() < 2) return null;

      alteredLine.append(args.get(0));
      alteredLine.append("[");
      alteredLine.append(args.get(1));
      alteredLine.append("];");
      return alteredLine.toString();
    }

    return null;
  }

}
