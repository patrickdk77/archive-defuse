// The command-line tests of pdf-defuse test/cli.test.ts, for archives.
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { expect } from 'chai';
import { build, fixture, fixtures, pythonList, runCli } from './helpers/util';

/** The fields of `inspect --json` output the tests read. */
interface InspectJson {
  status: string;
  findings: Array<{ category: string; detail: string; action: string; location?: string }>;
}

describe('command-line tool', () => {
  let dir: string;
  const fx = (name: string) => path.join(fixtures, name);
  before(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'archive-defuse-cli-'));
    fs.writeFileSync(path.join(dir, 'keep.js'), "module.exports = { plugins: [{ kind: 'file', name: 'keepall', accepts: () => true, process: async () => 'passed' }] };\n");
    fs.writeFileSync(path.join(dir, 'config.js'), "module.exports = { actionOverrides: [{ category: 'NAME', action: 'reject' }], limits: { entries: 1 } };\n");
    fs.writeFileSync(path.join(dir, 'escape.zip'), build.zip([build.text('esc\u001b[2Jape.txt')]));
  });
  after(() => fs.rmSync(dir, { recursive: true, force: true }));

  it('inspects with exit codes 0, 1 and 2', () => {
    expect(runCli(['inspect', fx('zip-clean.zip'), '--keep-type', 'txt']).status).to.equal(0);
    const traversal = runCli(['inspect', fx('zip-traversal.zip')]);
    expect(traversal.status).to.equal(1);
    expect(traversal.stdout.toString()).to.include('NAME/TRAVERSAL');
    expect(runCli(['inspect', fx('zip-zipcrypto.zip')]).status).to.equal(2);
  });

  it('prints JSON', () => {
    const r = JSON.parse(runCli(['inspect', fx('zip-traversal.zip'), '--json']).stdout.toString()) as InspectJson;
    expect(r.status).to.equal('strippable');
    expect(r.findings.some(f => f.detail === 'TRAVERSAL')).to.equal(true);
  });

  it('defuses to a file and to stdout, reading stdin', () => {
    const out = path.join(dir, 'out.zip');
    expect(runCli(['defuse', fx('zip-traversal.zip'), out, '--keep-type', 'txt']).status).to.equal(1);
    expect(pythonList('zip', fs.readFileSync(out)).map(e => e[0])).to.deep.equal(['outside.txt', 'docs/up-two.txt', 'safe.txt']);
    const piped = runCli(['defuse', '-', '-', '--keep-type', 'txt'], { input: fixture('zip-traversal.zip') });
    expect(piped.status).to.equal(1);
    expect(Buffer.compare(piped.stdout, fs.readFileSync(out))).to.equal(0);
    // The report goes to stderr when the archive goes to stdout.
    expect(piped.stderr.toString()).to.include('result: defused');
  });

  it('exits 2 for a rejected defuse and writes no output file', () => {
    const out = path.join(dir, 'rejected.zip');
    expect(runCli(['defuse', fx('zip-zipcrypto.zip'), out]).status).to.equal(2);
    expect(fs.existsSync(out)).to.equal(false);
  });

  it('refuses an output that is its input', () => {
    const copy = path.join(dir, 'same.zip');
    fs.copyFileSync(fx('zip-clean.zip'), copy);
    expect(runCli(['defuse', copy, copy]).status).to.equal(3);
    expect(fs.readFileSync(copy).equals(fixture('zip-clean.zip'))).to.equal(true);
  });

  it('loads plugin modules, keeps types with --keep-type and defuses inner archives', () => {
    const detail = (args: string[]) => (JSON.parse(runCli(['inspect', ...args, '--json']).stdout.toString()) as InspectJson).findings.filter(f => f.category === 'ENTRY').map(f => f.detail);
    expect(detail([fx('zip-clean.zip')])).to.deep.equal(['NO_PLUGIN', 'NO_PLUGIN']);
    expect(detail([fx('zip-clean.zip'), '--plugin', path.join(dir, 'keep.js')])).to.deep.equal(['PLUGIN_PASSED', 'PLUGIN_PASSED']);
    expect(detail([fx('gzip-tar.tar.gz'), '--defuse-inner-archives', '--keep-type', 'txt'])).to.deep.equal(['PLUGIN_PASSED', 'PLUGIN_PASSED']);
  });

  it('strips metadata with --strip-metadata', () => {
    const out = path.join(dir, 'stripped.zip');
    expect(runCli(['defuse', fx('zip-comments.zip'), out, '--strip-metadata', '--keep-type', 'txt']).status).to.equal(1);
    expect(fs.readFileSync(out).includes(Buffer.from('comment'))).to.equal(false);
  });

  it('loads a config module and parses limits', () => {
    const rejects = (args: string[]) => {
      const r = runCli(['inspect', fx('zip-traversal.zip'), '--config', path.join(dir, 'config.js'), ...args, '--json']);
      return { status: r.status, rejects: (JSON.parse(r.stdout.toString()) as InspectJson).findings.filter(f => f.action === 'reject').map(f => `${f.category}/${f.detail}`) };
    };
    // The config rejects name findings and allows one entry; a --limit flag replaces only the limit it names.
    expect(rejects(['--limit', 'entries=10'])).to.deep.equal({ status: 2, rejects: ['NAME/TRAVERSAL', 'NAME/TRAVERSAL'] });
    expect(rejects(['--limit', 'fileSize=1mb'])).to.deep.equal({ status: 2, rejects: ['LIMIT/ENTRY_COUNT'] });
    expect(runCli(['inspect', fx('zip-traversal.zip'), '--limit', 'decompressedBytes=1kb']).status).to.equal(1);
    expect(runCli(['inspect', fx('zip-traversal.zip'), '--limit', 'entries=many']).status).to.equal(3);
    const small = runCli(['inspect', '-', '--limit', 'fileSize=100'], { input: fixture('zip-traversal.zip') });
    expect(small.stdout.toString()).to.include('LIMIT/FILE_SIZE');
  });

  it('takes the password from a file or the environment, never a flag', () => {
    const enc = fx('zip-zipcrypto.zip');
    fs.writeFileSync(path.join(dir, 'pw.txt'), 'correct horse\n');
    expect(runCli(['inspect', enc, '--password-file', path.join(dir, 'pw.txt')]).status).to.equal(1);
    expect(runCli(['inspect', enc], { env: { ARCHIVE_DEFUSE_PASSWORD: 'correct horse' } }).status).to.equal(1);
    const flag = runCli(['inspect', enc, '--password', 'correct horse']);
    expect(flag.status).to.equal(3);
    expect(flag.stderr.toString()).to.include('not on the command line');
    const typo = runCli(['inspect', enc, '--pasword=correct horse']);
    expect(typo.stderr.toString()).to.include('Unknown option --pasword=...');
    expect(typo.stderr.toString()).to.not.include('correct horse');
  });

  it('reads one password per line from the password file, and one password from the environment', () => {
    const opened = (args: string[], env: NodeJS.ProcessEnv = {}) => {
      const r = runCli(['inspect', fx('zip-zipcrypto.zip'), ...args, '--json'], { env });
      return { status: r.status, opened: (JSON.parse(r.stdout.toString()) as InspectJson).findings.filter(f => f.category === 'ENCRYPTED' && f.action !== 'info').map(f => f.detail) };
    };
    const file = (name: string, text: string) => {
      fs.writeFileSync(path.join(dir, name), text);
      return ['--password-file', path.join(dir, name)];
    };
    expect(opened(file('several.txt', 'nope\r\n\r\nwrong\n\ncorrect horse'))).to.deep.equal({ status: 1, opened: ['DECRYPTED'] });
    expect(opened(file('crlf.txt', 'correct horse\r\n'))).to.deep.equal({ status: 1, opened: ['DECRYPTED'] });
    // Spaces are part of a password.
    expect(opened(file('spaces.txt', ' correct horse \n'))).to.deep.equal({ status: 2, opened: ['PASSWORD_REQUIRED'] });
    expect(opened(file('blank.txt', '\n\r\n\n'))).to.deep.equal({ status: 2, opened: ['PASSWORD_REQUIRED'] });
    // The environment holds one password, so a line break in it is part of that password.
    expect(opened([], { ARCHIVE_DEFUSE_PASSWORD: 'nope\ncorrect horse' })).to.deep.equal({ status: 2, opened: ['PASSWORD_REQUIRED'] });
    // The password file replaces the environment's password.
    expect(opened(file('wrong.txt', 'nope\n'), { ARCHIVE_DEFUSE_PASSWORD: 'correct horse' })).to.deep.equal({ status: 2, opened: ['PASSWORD_REQUIRED'] });
    const empty = runCli(['inspect', fx('zip-empty-password.zip'), '--password-file', path.join(dir, 'blank.txt'), '--json']);
    expect((JSON.parse(empty.stdout.toString()) as InspectJson).findings.map(f => f.detail)).to.include('EMPTY_PASSWORD');
  });

  it('prints control characters from entry names as escapes', () => {
    const text = runCli(['inspect', path.join(dir, 'escape.zip')]).stdout.toString();
    expect(text).to.include('esc\\u001b[2Jape.txt');
    expect(text).to.not.include('\u001b');
  });

  it('exits 3 on usage errors', () => {
    expect(runCli([]).status).to.equal(3);
    expect(runCli(['inspect']).status).to.equal(3);
    const bogus = runCli(['inspect', fx('zip-clean.zip'), '--bogus']);
    expect(bogus.status).to.equal(3);
    expect(bogus.stderr.toString()).to.include('Unknown option --bogus');
    expect(runCli(['defuse', path.join(dir, 'missing.zip'), path.join(dir, 'x.zip')]).status).to.equal(3);
  });
});
