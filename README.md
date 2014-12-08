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


--- before demonstration
in mysql, issue the following commands before each iteration of demo:
use saradb
drop table sara_log; drop table sara_card;

--- during demonstration
SELECT * FROM sara_log; SELECT * FROM sara_card order by date;
