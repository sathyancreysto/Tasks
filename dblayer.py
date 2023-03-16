import psycopg2
conn_string=("host='localhost' dbname='task' user='postgres' password='ddhxm0333' port='5432'")

def dbTransactionSelect(query):
    connection = psycopg2.connect(conn_string)
    try:
        select_cursor = connection.cursor()
        select_cursor.execute(query)
        query_result=select_cursor.fetchall()
        connection.commit()
        if len(query_result)>0:
            columns = select_cursor.description
            result = [{columns[index][0]:column for index, column in enumerate(value)} for value in query_result]
            return result
        if len(query_result)==0:
            return "No data Found"
    except Exception as ex:
        return str(ex)
    finally:
        select_cursor.close()
        connection.close()
def dbTransactionIUD(query):
    connection = psycopg2.connect(conn_string)
    try:
        iud_cursor = connection.cursor()
        iud_cursor.execute(query)
        connection.commit()
        return "Success"
    except Exception as ex:
        return str(ex)
    finally:
        iud_cursor.close()
        connection.close()
