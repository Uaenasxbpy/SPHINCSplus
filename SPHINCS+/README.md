# SPHINCS+算法
- 3种哈希算法可选择:`haraka、sha256、shake256`
- 3种强度可选择:`128、192、256`
- 每种以上9种算法还有fast(快)和small(小)2种区别，共计18种类别。
- 第三轮提交的源码 reference版本中的simple版本，未使用robot版本
### 运行测试代码（只用了20轮）
```shell
# 编译运行
make benchmark
```