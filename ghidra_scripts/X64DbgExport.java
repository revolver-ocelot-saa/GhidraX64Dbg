/* ###
 * MIT LICENSE
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Iterator;
import com.google.gson.GsonBuilder;
import com.google.gson.annotations.Expose;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Bookmark;

public class X64DbgExport extends GhidraScript {

	/** Maps to the structure of an X64 database */
	public class X64Database {
		
		/** Generic class for properties that are present on all X64 objects*/
		public abstract class X64Property {
			
			/** Lower case name of the module */
			@Expose
			public String module = currentProgram.getName().toLowerCase();
			
			/** Whether a human created the label or not (non-manual items do not appear by default in the UI) */
			@Expose
			public boolean manual = true;
		}
		
		/** Generic class for properties found on all address specific X64 objects */
		public abstract class X64Location extends X64Property {
			
			/** Address for the hex string label*/
			@Expose
			public String address;		
		}
		
		/** Maps to an X64 bookmark object */
		public class X64BookMark extends X64Location {
			
			public X64BookMark(String address) {
				this.address = address;
			}
			
		}
		
		/** Maps to an X64 database label entry object */
		public class X64Label extends X64Location {
			
			@Expose
			public String text; // Label content
			
			/**
			 * Default constructor for the X64 label
			 * 
			 * @param address Address to place the label
			 * @param text    Content of the label
			 */
			public X64Label(String address, String text) {
				this.address = address;
				this.text = text;
			}
		}

		/** Maps to an X64 database function entry object */
		public class X64Function extends X64Property {
			
			@Expose
			public String start; // Start address of the function (hex string)
			
			@Expose
			public String end; // End address of the function (hex string)
			
			@Expose
			public String icount; // Number of instructions in hex (optional)

			/**
			 * Default constructor for an X64 function object
			 * 
			 * @param start  Start address of the function
			 * @param end    End address of the function
			 * @param icount The number of instructions in the function
			 */
			public X64Function(String start, String end, String icount) {
				this.start = start;
				this.end = end;
				this.icount = icount;
			}
		}
		
		/** List of all bookmarks within the X64 database */
		@Expose
		public ArrayList<X64BookMark> bookmarks = new ArrayList<X64BookMark>();
		
		/** List of all functions within the X64 database */
		@Expose
		public ArrayList<X64Function> functions = new ArrayList<X64Function>();

		/** List of all labels within the X64 database */
		@Expose
		public ArrayList<X64Label> labels = new ArrayList<X64Label>();

		/** Comments are actually the same as labels at the moment */
		@Expose
		public ArrayList<X64Label> comments = new ArrayList<X64Label>();

		// The image base is used across the program
		private Address imageBase = currentProgram.getImageBase();
		
		/** Populates the bookmarks within the X64 database */
		public void populateBookmarks() {
			
			// Only grab the user added bookmarks (or else we would end up battering comments)
			Iterator<Bookmark> bookMarkIterator = currentProgram.getBookmarkManager().getBookmarksIterator("Note");
			while (bookMarkIterator.hasNext()) {
				Bookmark bookMark = bookMarkIterator.next();				
				String address = "0x" + Long.toHexString(bookMark.getAddress().subtract(imageBase));
				bookmarks.add(new X64BookMark(address));
			}
		}
		
		/** Populates the functions and labels within the X64 database */
		public void populateFunctions() {
			for (Function function : currentProgram.getFunctionManager().getFunctions(true)) {
				AddressSetView functionBody = function.getBody();

				// Retrieve required properties
				String start = "0x" + Long.toHexString(functionBody.getMinAddress().subtract(imageBase));
				String end = "0x" + Long.toHexString(functionBody.getMaxAddress().subtract(imageBase));
				String label = function.getName();
				String instructionCount = "0x" + Long.toHexString(functionBody.getNumAddresses());

				this.functions.add(new X64Function(start, end, instructionCount));
				this.labels.add(new X64Label(start, label));
			}
		}

		/**
		 * Adds comments labels to the X64 database. Does not retrieve plate comments
		 * and pre/post comments as X64 does not really support them.
		 */
		public void populateComments() {

			Listing listing = currentProgram.getListing();

			for (Address commentedAddress : listing.getCommentAddressIterator(currentProgram.getMemory(), true)) {

				CodeUnit cu = listing.getCodeUnitAt(commentedAddress);

				// Skip empty code units or empty comment
				if (cu == null) {
					continue;
				}

				String comment;
				String start = "0x" + Long.toHexString(commentedAddress.subtract(imageBase));

				// Process EOL comments
				comment = cu.getComment(CodeUnit.EOL_COMMENT);
				if (comment != null && comment.length() != 0) {
					this.comments.add(new X64Label(start, comment));
				}

				// Process repeatable comments
				comment = cu.getComment(CodeUnit.REPEATABLE_COMMENT);
				if (cu.getComment(CodeUnit.REPEATABLE_COMMENT) != null) {
					this.comments.add(new X64Label(start, comment));
				}
			}
		}
	}

	/** Entry point for the Ghidra script */
	@Override
	protected void run() throws Exception {

		// Prompt user for output path
		File outputPath = askFile("Select Output File (Type desired name if file does not exist)", "Ok");

		// Create and populate x64Database
		var x64Database = new X64Database();

		println("Running function extraction...");
		x64Database.populateFunctions();

		println("Running comment extraction...");
		x64Database.populateComments();
		
		println("Running bookmarks extraction...");
		x64Database.populateBookmarks();

		// Serialize the file to JSON
		var gson = new GsonBuilder().excludeFieldsWithoutExposeAnnotation().setPrettyPrinting().create();
		Files.write(Paths.get(outputPath.getAbsolutePath()), gson.toJson(x64Database).getBytes(),
				StandardOpenOption.CREATE);
	}

}
