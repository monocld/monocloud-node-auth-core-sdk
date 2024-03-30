export default {
  extensions: {
    ts: 'module',
    mjs: true,
  },
  files: ['tests/oauth4webapi/**/*.ts', '!tests/oauth4webapi/**/_*.ts'],
  workerThreads: false,
  nodeArguments: ['--enable-source-maps'],
};
