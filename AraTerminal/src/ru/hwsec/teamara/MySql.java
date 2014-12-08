package ru.hwsec.teamara;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.logging.Level;
import java.util.logging.Logger;

public class MySql {

	// Smart card expires after SMART_CARD_LIFE_CYCLE years.
	final static short SMART_CARD_LIFE_CYCLE = 3;

	// Terminal expires after TERMINAL_LIFE_CYCLE years.
	final static short TERMINAL_LIFE_CYCLE = 5;
	
	private Connection con = null;
	private Statement st = null;
	private ResultSet rs = null;

	private String database = "saradb";
	private String url = "jdbc:mysql://localhost:3306/" + database;
	private String user = "sara";
	private String password = "";


	/*
	 * Create the 4 tables that are used.
	 */
	public void initializedb() {
		String query = "CREATE TABLE IF NOT EXISTS sara_card ( "
				+ "cardID MEDIUMINT UNSIGNED NOT NULL PRIMARY KEY, "
				+ "INDEX USING BTREE(cardID), "
				+ "balance SMALLINT UNSIGNED NOT NULL, "
				+ "charged TINYINT(1) NOT NULL, "
				+ "publicKey VARCHAR(100) NOT NULL, "
				+ "expDATE DATE NOT NULL " + ")";
		execute_query(query);

		query = "CREATE TABLE IF NOT EXISTS sara_terminal ( "
				+ "termID MEDIUMINT UNSIGNED NOT NULL PRIMARY KEY, "
				+ "INDEX USING BTREE(termID), "
				+ "publicKey VARCHAR(100) NOT NULL, "
				+ "expDATE DATE NOT NULL " + ")";
		execute_query(query);

		query = "CREATE TABLE IF NOT EXISTS sara_user ( "
				+ "id MEDIUMINT NOT NULL AUTO_INCREMENT PRIMARY KEY,"
				+ "userID MEDIUMINT UNSIGNED NOT NULL, "
				+ "cardID MEDIUMINT UNSIGNED NOT NULL, "
				+ "name VARCHAR(100) NOT NULL, " + "address VARCHAR(100), "
				+ "valid TINYINT(1) NOT NULL " + ")"; // boolean
		execute_query(query);

		query = "CREATE TABLE IF NOT EXISTS sara_log ( "
				+ "id MEDIUMINT NOT NULL AUTO_INCREMENT PRIMARY KEY,"
				+ "cardID MEDIUMINT UNSIGNED NOT NULL, "
				// Max value of balance is 65535.
				+ "balance SMALLINT UNSIGNED NOT NULL, "
				// Last transaction can be {-250,..,200}.
				+ "transaction SMALLINT NOT NULL, "
				+ "termID MEDIUMINT UNSIGNED NOT NULL, "					
				+ "date DATETIME NOT NULL , "
				+ "sig_card VARCHAR(85) NOT NULL,"         // Average signature in String is length 76.
				+ "sig_term VARCHAR(85) NOT NULL" + ")";   // Average signature in String is length 76.
		execute_query(query);
		
		// TESTING...
		addcard(161, 0, "PK"); // Start with 0 balance.
	}

	/*
	 *  Add entries to the table sara_log.
	 *  - an entry should not be edited or deleted.
	 *  (e.g (1001, 10, -50, 2001, "2014-11-27 15:01:35", "sig_card", "sig_term" );)
	 *  After an entry the balance must be updated using the 
	 *  updateBalance function.
	 */
	public boolean addlog(int tcardID, short tbalance, short ttransaction, int termID, String tdate, String tsig_card, String tsig_term) {
		String query = "INSERT INTO sara_log ( "
			+ "cardID, balance, transaction, termID, date, sig_card, sig_term)"
			+ "VALUES ("
			+ tcardID + "," 
			+ tbalance + "," 
			+ ttransaction + "," 
			+ termID + ","
			+ "\"" + tdate + "\","
			+ "\"" + tsig_card + "\","
			+ "\"" + tsig_term + "\""
			+ ")";
		return execute_query(query);
	}
	
	/*
	 * Update the balance for cardID in table sara_card. 
	 */
	public boolean updateBalance(int cardID, int new_balance) {
		String query = "UPDATE sara_card " 
			+ " SET balance=" 
			+ new_balance
			+ " WHERE cardID=" 
			+ cardID;
		return execute_query(query);
	}
	
	/*
	 * Return the balance of cardID in the table sara_card.
	 */
	public int get_balance(int cardID){
		int tbalance = -1;
		try {
			con = DriverManager.getConnection(url, user, password);
			st = con.createStatement();

			String query = "SELECT balance "
				+ " FROM sara_card "
				+ " WHERE cardID=" 
				+ cardID;
			rs = st.executeQuery(query);

			if (rs.next()) {
				return Integer.parseInt(rs.getString(1));
			}
			else
				return -1;
			
		} catch (SQLException ex) {
			Logger lgr = Logger.getLogger(MySql.class.getName());
			lgr.log(Level.SEVERE, ex.getMessage(), ex);
			return -2;
        } catch(NumberFormatException e) {
        	System.out.println("Input is not a number.. this has to be fixed asap.");
        	System.exit(1);
		} finally {
			try {
				if (rs != null) {
					rs.close();
				}
				if (st != null) {
					st.close();
				}
				if (con != null) {
					con.close();
				}

			} catch (SQLException ex) {
				Logger lgr = Logger.getLogger(MySql.class.getName());
				lgr.log(Level.WARNING, ex.getMessage(), ex);
				System.out.println("Entry was inserted but db was not closed.");
				System.exit(1);
			}
		}
		return tbalance; // 
	}

	public boolean charge(int cardID){
		try {
			con = DriverManager.getConnection(url, user, password);
			st = con.createStatement();

			String query = "SELECT charged "
				+ " FROM sara_card "
				+ " WHERE cardID=" 
				+ cardID;
			rs = st.executeQuery(query);

			if (rs.next()) {
				System.out.println(Integer.parseInt(rs.getString(1)));
				if (Integer.parseInt(rs.getString(1)) == 1)
					return true;
				else
					return false;
			}
			else
				return false;
			
		} catch (SQLException ex) {
			Logger lgr = Logger.getLogger(MySql.class.getName());
			lgr.log(Level.SEVERE, ex.getMessage(), ex);
			return false;
        } catch(NumberFormatException e) {
        	System.out.println("Input is not a number.. this has to be fixed asap.");
        	System.exit(1);
		} finally {
			try {
				if (rs != null) {
					rs.close();
				}
				if (st != null) {
					st.close();
				}
				if (con != null) {
					con.close();
				}

			} catch (SQLException ex) {
				Logger lgr = Logger.getLogger(MySql.class.getName());
				lgr.log(Level.WARNING, ex.getMessage(), ex);
				System.out.println("Entry was inserted but db was not closed.");
				System.exit(1);
			}
		}
		return false; // 
	}

	public boolean charged(int cardID, int newBalance) {
		String query = "UPDATE sara_card SET charged=0 WHERE cardID=" + cardID;
		execute_query(query);
		query = "UPDATE sara_card SET balance=" + newBalance + " WHERE cardID=" + cardID;
		return execute_query(query);
	}

	
	/*
	 * Mark card as invalid. If a cardID exists:
	 * - the attribute valid of the previous entry in table sara_user must change to false.
	 * - the previous row in the table sara_card must be removed.
	 */
	public void card_invalid() {
		
	}
	
	/*
	 * Add new user to the database.
	 * - revoke previous card
	 * - add new entry to the sara_card table.
	 * Entries in this table must not be removed. It is only allowed to change 
	 * the valid status whenever a new entry with a new card in inserted.
	 */
	public boolean adduser(int userID, int cardID, String name, String address) {
		// search for existing cards, if exists remove it.
		card_invalid();
		// System.out.print("Name: ");
		// Scanner in = new Scanner( System.in );
		String query = "INSERT INTO sara_user ( "
				+ "userID, cardID, name, address, valid)" + "VALUES (" + userID
				+ "," + cardID + "," + "\"" + name + "\"," + "\"" + address
				+ "\"," + 1 // It is always valid, when it is activated.
				+ ")";
		return execute_query(query);
	}

	/*
	 * This function must be called only after the adduser is completed.
	 */
	private boolean addcard(int tcardID, int tbalance, String publickey) {
		String query = "INSERT INTO sara_card ( "
				+ "cardID, balance, charged, publicKey, expDATE)" + "VALUES ("
				+ tcardID + "," 
				+ tbalance + "," 
				+ 1	+ "," // It will not be charged for this month.
				+ "\"" + publickey + "\"," 
				+ "curdate() + INTERVAL " + SMART_CARD_LIFE_CYCLE + " YEAR" // Expire date is in 4 years.
				+ ")";
		return execute_query(query);
	}

	/*
	 * Add new terminal to the database.
	 * - create new entry to the table sara_terminal
	 */
	public boolean addterminal(int termID, String publickey) {
		String query = "INSERT INTO sara_card ( "
				+ "termID, publicKey, expDATE)" + "VALUES (" + termID + ","
				+ "\"" + publickey + "\"," + "curdate() + INTERVAL "
				+ TERMINAL_LIFE_CYCLE + " YEAR"
				+ ")";
		return execute_query(query);
	}
	
	/*
	 * On the 1st of each month, this function must update all the
	 * "boolean" of table sara_card and attribute charged to 1.
	 * (We do not keep track of what was the value.
	 */
	public boolean new_month(){
		// THE SYSADMIN MUST CALL THIS FUNCTION.
		return true;
	}

	/**
	 * Execute an mysql query which does not return anything 
	 * (e.g. not containing SELECT).
	 * @param The query that will be executed to the mysql server.
	 * @return True if it was executed successfully, otherwise false.
	 */
	private boolean execute_query(String query){
		try {
			con = DriverManager.getConnection(url, user, password);
			st = con.createStatement();
			st.executeUpdate(query);
		} catch (SQLException ex) {
			Logger lgr = Logger.getLogger(MySql.class.getName());
			lgr.log(Level.SEVERE, ex.getMessage(), ex);
			return false;
		} finally {
			try {
				if (rs != null) {
					rs.close();
				}
				if (st != null) {
					st.close();
				}
				if (con != null) {
					con.close();
				}

			} catch (SQLException ex) {
				Logger lgr = Logger.getLogger(MySql.class.getName());
				lgr.log(Level.WARNING, ex.getMessage(), ex);
				System.out.println("Entry was inserted but db was not closed.");
				System.exit(1);
			}
		}		
		return true;
	}
	
	MySql() {
		/*
		 *  Create the database if it does not exist 
		 *  and give full access to user sara.
		 *  Root password for mysql must be empty and
		 *  user sara must have been created already.
		 */
		try {
			// Check if db exists.
			con = DriverManager.getConnection("jdbc:mysql://localhost:3306/",
					"root", "");
			st = con.createStatement();
			rs = st
					.executeQuery("SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME = '"
							+ database + "'");
			if (rs.next()) {
				System.out.println(rs.getString(1) + " exists.");
			} else {
				st.executeUpdate("CREATE DATABASE " + database);
				st.executeUpdate("GRANT ALL PRIVILEGES ON " + database
						+ ".* to " + user + "@localhost");
				System.out.println("Database '" + database
						+ "' has been created.");
			}

		} catch (SQLException ex) {
			Logger lgr = Logger.getLogger(MySql.class.getName());
			lgr.log(Level.SEVERE, ex.getMessage(), ex);

		} finally {
			try {
				if (rs != null) {
					rs.close();
				}
				if (st != null) {
					st.close();
				}
				if (con != null) {
					con.close();
				}

			} catch (SQLException ex) {
				Logger lgr = Logger.getLogger(MySql.class.getName());
				lgr.log(Level.WARNING, ex.getMessage(), ex);
			}
		}
	}

}
