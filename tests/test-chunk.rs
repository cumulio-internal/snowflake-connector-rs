mod common;

use futures::StreamExt;
use snowflake_connector_rs::Result;

#[tokio::test]
async fn test_fetch_all_ordered() -> Result<()> {
    // Arrange
    let client = common::connect()?;

    // Act
    let session = client.create_session().await?;
    let query = "SELECT * FROM \"SNOWFLAKE_SAMPLE_DATA\".\"TPCH_SF10\".\"ORDERS\" ORDER BY \"O_ORDERKEY\" ASC LIMIT 1000000";
    let executor = session.execute(query).await?;

    // Assert
    let mut row_count = 0;
    let prev_order_key = 0;
    let mut stream = executor.fetch_all_ordered().await;
    while let Some(Ok(row)) = stream.next().await {
        row_count += 1;
        if prev_order_key >= row.get::<u64>("O_ORDERKEY").unwrap() {
            panic!(
                "Order key is not in order: received {} but already encountered {}",
                row.get::<u64>("O_ORDERKEY").unwrap(),
                prev_order_key
            )
        }
    }

    assert!(
        row_count == 1000000,
        "Expected 1000000 rows but got {row_count}"
    );
    Ok(())
}

#[tokio::test]
async fn test_download_chunked_results() -> Result<()> {
    // Arrange
    let client = common::connect()?;

    // Act
    let session = client.create_session().await?;
    let query =
        "SELECT SEQ8() AS SEQ, RANDSTR(1000, RANDOM()) AS RAND FROM TABLE(GENERATOR(ROWCOUNT=>10000))";
    let rows = session.query(query).await?;

    // Assert
    assert_eq!(rows.len(), 10000);
    assert!(rows[0].get::<u64>("SEQ").is_ok());
    assert!(rows[0].get::<String>("RAND").is_ok());
    assert!(rows[0].column_names().contains(&"SEQ"));
    assert!(rows[0].column_names().contains(&"RAND"));

    let columns = rows[0].column_types();
    assert_eq!(
        columns[0]
            .column_type()
            .snowflake_type()
            .to_ascii_uppercase(),
        "FIXED"
    );
    assert!(!columns[0].column_type().nullable());
    assert_eq!(columns[0].index(), 0);
    assert_eq!(
        columns[1]
            .column_type()
            .snowflake_type()
            .to_ascii_uppercase(),
        "TEXT"
    );
    assert!(!columns[1].column_type().nullable());
    assert_eq!(columns[1].index(), 1);

    Ok(())
}

#[tokio::test]
async fn test_query_executor() -> Result<()> {
    // Arrange
    let client = common::connect()?;

    // Act
    let session = client.create_session().await?;
    let query =
        "SELECT SEQ8() AS SEQ, RANDSTR(1000, RANDOM()) AS RAND FROM TABLE(GENERATOR(ROWCOUNT=>10000))";

    let executor = session.execute(query).await?;
    let mut rows = Vec::with_capacity(10000);
    while let Some(mut r) = executor.fetch_next_chunk().await? {
        rows.append(&mut r);
    }

    // Assert
    assert_eq!(rows.len(), 10000);
    assert!(rows[0].get::<u64>("SEQ").is_ok());
    assert!(rows[0].get::<String>("RAND").is_ok());
    assert!(rows[0].column_names().contains(&"SEQ"));
    assert!(rows[0].column_names().contains(&"RAND"));

    Ok(())
}
