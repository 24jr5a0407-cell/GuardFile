const fs = require('fs');
const path = require('path');
const { getDb } = require('../config/database');

async function migrate() {
  console.log('[Migration] Starting database migration...');
  const db = await getDb();
  const schemaPath = path.resolve(__dirname, 'schema.sql');
  const schemaSql = fs.readFileSync(schemaPath, 'utf8');

  try {
    if (db.exec) {
      await db.exec(schemaSql);
    } else {
      await db.query(schemaSql);
    }
    console.log('[Migration] Database schema migrated successfully.');
  } catch (err) {
    console.error('[Migration Error]', err.message);
    throw err;
  }
}

if (require.main === module) {
  migrate()
    .then(() => {
      console.log('[Migration] Complete.');
      process.exit(0);
    })
    .catch((err) => {
      console.error('[Migration Failed]', err);
      process.exit(1);
    });
}

module.exports = { migrate };
