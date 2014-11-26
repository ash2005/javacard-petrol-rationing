package ru.hwsec.teamara;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.logging.Level;
import java.util.logging.Logger;


public class MySql {
	
    private Connection con = null;
    private Statement st = null;
    private ResultSet rs = null;
	
    private String database = "saradb";
	private String url = "jdbc:mysql://localhost:3306/" + database;
	private String user = "sara";
	private String password = "";
	
	MySql (){
		
		// Root creates the database if it does not exist and gives full access to user sara.
        try {
        	// Check if db exists.
            con = DriverManager.getConnection("jdbc:mysql://localhost:3306/", "root", "");
            st = con.createStatement();
            rs = st.executeQuery("SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME = '" + database + "'");
            if (rs.next()) {
                System.out.println(rs.getString(1) + " exists.");
            }
            else {
            	st.executeUpdate("CREATE DATABASE " + database );
            	st.executeUpdate("GRANT ALL PRIVILEGES ON " + database + ".* to " + user + "@localhost");
            	System.out.println("Database '" + database + "' has been created.");
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
	
	public void initializedb(){
        try {
            con = DriverManager.getConnection(url, user, password);
            st = con.createStatement();
            
            String query = "SCREATE TABLE IF NOT EXISTS ";
            //rs = st.executeQuery(query);
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
	
	// Called whenever a new user is created.
	public void adduser(){
		
	}
	
	// Called to add entries to the logs.
	public void addentry(){
		
	}
}
