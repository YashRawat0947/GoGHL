import { MongoClient, type Db } from 'mongodb';
import { config } from './config.js';

let client: MongoClient | undefined;
let dbPromise: Promise<Db> | undefined;

export function getDb(): Promise<Db> {
  if (!dbPromise) {
    client = new MongoClient(config.mongoUrl);

    dbPromise = client.connect().then(() => client!.db());
  }

  return dbPromise;
}