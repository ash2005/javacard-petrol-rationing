javacard-petrol-rationing
=========================

Radboud University, Hardware Security course, JavaCard project

--- create db:
- sudo apt-get install mysql-server mysql-client libmysql-java (leave root password empty, for now)
- mysql -u root
  + CREATE USER 'sara'@'localhost';
  + CREATE database saradb;  				// Done by script.
  + grant all privileges on saradb.* to sara@localhost  // Done by script.

--- configure eclipse:
go to: Project, click Properties, select Java Build Path, and choose the Libraries tab. Then select 'Add External JARs', and find '/usr/share/java/mysql-connector-java.jar'. 
source: https://help.ubuntu.com/community/JDBCAndMySQL
