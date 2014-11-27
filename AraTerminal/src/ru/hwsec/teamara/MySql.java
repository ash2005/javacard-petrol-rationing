package ru.hwsec.teamara;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.logging.Level;
import java.util.logging.Logger;

import java.util.Scanner;

public class MySql {

	private Connection con = null;
	private Statement st = null;
	private ResultSet rs = null;

	private String database = "saradb";
	private String url = "jdbc:mysql://localhost:3306/" + database;
	private String user = "sara";
	private String password = "";

	MySql() {

		// Root creates the database if it does not exist and gives full access
		// to user sara.
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

		// Sara user... testing.
		try {
			con = DriverManager.getConnection(url, user, password);
			st = con.createStatement();
			rs = st.executeQuery("SELECT VERSION()");

			if (rs.next()) {
				System.out.println(rs.getString(1));
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

	public void initializedb() {
		try {
			con = DriverManager.getConnection(url, user, password);
			st = con.createStatement();

			String query = "CREATE TABLE IF NOT EXISTS sara_card ( "
					+ "cardID MEDIUMINT UNSIGNED NOT NULL PRIMARY KEY, "
					+ "INDEX USING BTREE(cardID), "
					+ "balance SMALLINT UNSIGNED NOT NULL, "
					+ "charged TINYINT(1) NOT NULL, "
					+ "publicKey VARCHAR(100) NOT NULL, "
					+ "expDATE DATETIME NOT NULL " + ")";
			st.executeUpdate(query);

			query = "CREATE TABLE IF NOT EXISTS sara_terminal ( "
					+ "termID MEDIUMINT UNSIGNED NOT NULL PRIMARY KEY, "
					+ "INDEX USING BTREE(termID), "
					+ "publicKey VARCHAR(100) NOT NULL, "
					+ "expDATE DATETIME NOT NULL " + ")";
			st.executeUpdate(query);

			query = "CREATE TABLE IF NOT EXISTS sara_user ( "
					+ "id MEDIUMINT NOT NULL AUTO_INCREMENT PRIMARY KEY,"
					+ "userID MEDIUMINT UNSIGNED NOT NULL, "
					+ "cardID MEDIUMINT UNSIGNED NOT NULL, "
					+ "name VARCHAR(100) NOT NULL, " + "address VARCHAR(100), "
					+ "valid TINYINT(1) NOT NULL " + ")"; // boolean
			st.executeUpdate(query);

			query = "CREATE TABLE IF NOT EXISTS sara_log ( "
					+ "id MEDIUMINT NOT NULL AUTO_INCREMENT PRIMARY KEY,"
					+ "cardID MEDIUMINT UNSIGNED NOT NULL, "
					// Max value is 65535.
					+ "balance SMALLINT UNSIGNED NOT NULL, "
					// last transaction can be {-250,..,200}
					+ "transaction SMALLINT NOT NULL, "
					+ "termID MEDIUMINT UNSIGNED NOT NULL, "					
					+ "date DATETIME NOT NULL , "
					+ "sig_card VARCHAR(100) NOT NULL,"
					+ "sig_term VARCHAR(100) NOT NULL" + ")";
			st.executeUpdate(query);

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

	/*
	 *  Add entries to the logs (sara_log).
	 *  - an entry cannot be changed or deleted.
	 *  (e.g (1001, 10, -50, 2001, "2014-11-27 15:01:35", "sig_card", "sig_term" );)
	 *  Also, update the new balance in the table sara_card.
	 */
	public boolean addlog(int tcardID, short tbalance, short ttransaction, int termID, String tdate, String tsig_card, String tsig_term) {

		try {
			con = DriverManager.getConnection(url, user, password);
			st = con.createStatement();

			//String query = "INSERT";
			//st.executeUpdate(query);
			
			// Update balance in sara_card for tcardID.

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
	
	/*
	 * Return the balance of cardID in the table sara_card.
	 */
	public int get_balance(int cardID){
		int tbalance = -1;
		
		return tbalance; // 
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
	 */
	public void adduser() {
		// search for existing cards, if exists remove it.
		card_invalid(); 
        //System.out.print("Name: ");
        //Scanner in = new Scanner( System.in );
		
	}
	
	/*
	 * Add new terminal to the database.
	 * - create new entry to the table sara_terminal
	 */
	public void addterminal() {

	}
	
	/*
	 * On the 1st of each month, this function must update all the
	 * "boolean" of table sara_card and attribute charged to 1.
	 * (We do not keep track of what was the value.
	 */
	public void new_month(){
		// THE SYSADMIN MUST CALL THIS FUNCTION.
		
	}
	
	
}
