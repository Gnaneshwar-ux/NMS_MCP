declare module "oracledb" {
  export interface ConnectionAttributes {
    user?: string;
    username?: string;
    password?: string;
    connectString?: string;
    transportConnectTimeout?: number;
    stmtCacheSize?: number;
    configDir?: string;
    walletLocation?: string;
    walletPassword?: string;
    httpsProxy?: string;
    httpsProxyPort?: number;
  }

  export interface ExecuteOptions {
    outFormat?: number;
    autoCommit?: boolean;
    maxRows?: number;
    fetchArraySize?: number;
    prefetchRows?: number;
  }

  export interface ResultMetaData {
    name: string;
    dbTypeName?: string;
    nullable?: boolean;
    precision?: number;
    scale?: number;
    byteSize?: number;
    fetchType?: number;
  }

  export interface ExecuteResult<T = Record<string, unknown>> {
    rows?: T[];
    rowsAffected?: number;
    metaData?: ResultMetaData[];
    warning?: Error;
  }

  export interface Connection {
    callTimeout: number;
    currentSchema?: string;
    dbDomain?: string;
    dbName?: string;
    serviceName?: string;
    oracleServerVersionString?: string;
    transactionInProgress?: boolean;
    module?: string;
    action?: string;
    execute<T = Record<string, unknown>>(
      sql: string,
      bindParams?: Record<string, unknown> | unknown[],
      options?: ExecuteOptions,
    ): Promise<ExecuteResult<T>>;
    break(): Promise<void>;
    breakExecution(): Promise<void>;
    close(): Promise<void>;
    ping(): Promise<void>;
    commit(): Promise<void>;
    rollback(): Promise<void>;
  }

  export interface OracleDbModule {
    OUT_FORMAT_OBJECT: number;
    CLOB: number;
    NCLOB: number;
    outFormat: number;
    fetchAsString: number[];
    getConnection(connectionAttributes: ConnectionAttributes): Promise<Connection>;
  }

  const oracledb: OracleDbModule;
  export default oracledb;
}
