/**
 * 第三方纯文本模块的类型声明。
 *
 * 这些文件在 wrangler.jsonc 的 rules 里被声明为 Text 类型 —— bundler 把它们
 * 当**字符串**打进 bundle，而不是当作可执行模块解析。因此：
 *   - 这里只声明 string，不声明函数/对象
 *   - tsconfig 的 include 不覆盖它们本身，只需要声明导入侧
 */
declare module "*/hyalite.js" {
  const source: string;
  export default source;
}
