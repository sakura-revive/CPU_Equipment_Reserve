# CPU Equipment Reserve

该项目可以帮助用户在中国药科大学的大型仪器共享平台上预约仪器。

## 运行要求
- python (Tested on python 3.12)

## 配置文件编辑须知

本程序使用后缀为`.yaml`的文件作为配置文件。这是一种纯文本文件，其语法参见[YAML官网](https://yaml.org/)。

本程序目前使用的配置文件中包含大量`object`（又称`mapping`、`hashes`、`dictionary`）的数据类型，即“键值对”，它们看起来是这样：
```yaml
# 配置选项key1的值是字符串"value1"
key1: "value1"

# 配置选项key2的值是数字-2
key2: -2
```

请按照语法规则编辑配置文件。如果您对这类文件的语法规则不熟悉，您只需要了解三点：
- 以井号（`#`）开头的行是注释，不会被程序读取；
- 请不要修改每一行的冒号前的内容；
- 在每行填写信息时，除非你知道自己在做什么，否则不建议删除双引号，也不要删除冒号和引号之间的空格；
- 请全程使用英文半角字符；
- 使用引号包裹的数字（如`"2"`）与不用引号包裹的数字（如`2`）有显著区别，编辑配置文件时请根据样例进行修改。

请尽量使用专业文本编辑器（如`VS Code`）创建和编辑配置文件。在Windows系统上创建和编辑配置文件时，请注意：
- 请配置文件夹选项以取消隐藏已知文件的扩展名，否则后缀为`.yaml`的文件可能难以创建；
  - 如无法显示文件扩展名，也可以选择复制已有的样例YAML文件，然后再重命名为目标名称。
- 请尽量避免使用记事本对YAML文件进行编辑，否则在保存文件时可能出现编码错误。
  - 如只能选择记事本编辑YAML文件，请在保存时使用“另存为”选项，保存文件类型选择“所有文件”，文件编码选择`UTF-8`而不是`ANSI`。

## 使用方法
### 获取本程序
```shell
git clone https://github.com/lucienshawls/CPU_Equipment_Reserve.git
cd CPU_Equipment_Reserve
```
### 安装环境
```shell
pip install -r requirements.txt
```
### 创建或编辑用户信息

在`./config/users`目录中，创建`xxxx.yaml`，或者原位复制`./config/users/sample_user.yaml`文件并将副本重命名为`xxxx.yaml`。

其中，`xxxx`可以任意拟定。

打开`xxxx.yaml`文件，并填写或修改字段的值。样例和字段解释如下：
```yaml
# 该用户的标识，可任意拟定
tag: "样例用户"

# 请将双引号内的值替换为该用户的用户名
username: "3212345678"

# 请将双引号内的值替换为该用户的密码
password: "mypassword"

# 此为该用户的登录方式，因为该程序目前仅支持统一身份认证登录，故请勿修改
login_method: "oauth"
```
额外说明：
- 请填写与登录方式匹配的用户名和密码，例如，登录方式是统一身份认证，则应填写可用于统一身份认证的用户名和密码；
- 拟定的`xxxx`会在创建或编辑预约信息时用到。

### 创建或编辑仪器表单

在`./config/forms`目录中，创建`xx.yaml`，或者原位复制`./config/forms/0.yaml`文件并将副本重命名为`xx.yaml`。

其中，`xx`对应某个仪器在大型仪器共享平台上的内部编号。

若要查询仪器的内部编号，请访问某个仪器的“使用预约”界面（即含有日历，可以点击某个时段进行预约的界面），此时浏览器地址栏显示的网址类似以下链接：

`https://dygx1.cpu.edu.cn/lims/!equipments/equipment/index.xx.reserv`

跟在`index.`后的`xx`即为该仪器的内部编号，该编号通常为一个数字。

打开`xx.yaml`文件，并填写或修改字段的值。样例和字段解释如下：
```yaml
# ============================================= 默认字段 ============================================= #
# 默认字段是指在表单中位于预约信息/样品信息下的字段
# 若要修改以下默认字段，请在修改后删除行首井号（#）以取消注释

# 主题，默认为“仪器使用预约”
#name: "仪器使用预约"

# 备注，默认为空
#description: ""

# 关联项目，默认为字符"0"，即不选
#project: "0"

# 经费卡号，默认为字符"0"，即不选
#fund_card_no: "0"

# 样品数，默认为数字1
#count: 1


# ============================================= 默认字段 ============================================= #

# ============================================= 其它字段 ============================================= #
# 其它字段是指在表单中除位于预约信息/样品信息下的其它字段
# 每个仪器的表单都不尽相同，这里仅给出一些样例，请参照文档填写

# 第一个填写项（文本框或单选按钮）
## 填写输入到文本框中的值，或选中的单选按钮的标签
extra_fields[1]: "2"

# 第二个填写项（复选框）
## 其中，“选项1”、“选项2”请更改为选项的实际标题，on是选中的状态，null是未选中的状态
## 不选的选项（即null行）可以写出，也可以省略；
extra_fields[2][选项1]: "null"
extra_fields[2][选项2]: "on"
extra_fields[2][选项3]: "null"
#extra_fields[2][选项4]: "null"
#extra_fields[2][其他]: "null"

# 第三个填写项（下拉列表）
## 填写选中的选项的编号（按从上到下的顺序，从1开始计算），填"0"则代表不选。
extra_fields[3]: "0"


# ============================================= 其它字段 ============================================= #

# ============================================ 非表单字段 ============================================ #
# 非表单字段是指在不在预约表单中出现的字段，用于控制程序的行为

# 创建预约的最早提前天数
days_in_advance: 0


# ============================================ 非表单字段 ============================================ #
```
额外说明：
- 默认字段共有5个，这些字段会在每一个仪器的预约表单中出现，并且均有其默认选项。这些字段通常不需要更改，如需更改，请将需要修改的字段的行首井号删除，以取消注释；
- 在默认字段中，关联项目、经费卡号字段属于下拉列表，应该填写选中的选项编号（按从上到下的顺序，从1开始计算编号），填`"0"`则代表不选；
- 出现在表单上，且不归属于“预约信息”和“样品信息”的字段是不同仪器的管理员自定义的字段。这些字段的规则如下：
  - 字段类型
    - 这些字段可以是各种形式，可能包括文本框、单选按钮、复选按钮、下拉列表等；
  - 键
    - 按照从上到下的顺序，将不同的字段从1开始编号，如第一个字段是文本框，第二组是复选框，第三组是下拉列表等；
    - 文本框、单选按钮和下拉列表类型的字段的键为`extra_field[编号]`，如`extra_field[1]`（表明该字段为第一个额外字段）；
    - 复选框类型的字段包括数个子字段，子字段的数量与复选按钮的个数一致，每个子字段的键为`extra_field[编号][选项名称]`，如`extra_field[2][小鼠]`、`extra_field[2][大鼠]`；
  - 值
    - 文本框类型的字段对应的值为文本内容，如`extra_field[1]: "文本内容"`（表明第一个额外字段输入了`文本内容`）；
    - 单选按钮类型的字段对应的值为选项名称，如`extra_field[1]: "动物实验中心"`（表明第一个额外字段选中了`动物实验中心`）；
    - 下拉列表类型的字段对应的值为选项编号（从上到下，从1开始），不选则填`"0"`如`extra_field[3]: "1"`（表明第三个额外字段选择了第一个选项）；
    - 复选框类型的字段的值为`"on"`或`"null"`，前者表明该选项被勾选了，后者表明该选项没有被勾选。如果某个选项没有被选择，则该选项可以省略。如`extra_field[2][小鼠]: "on"`（表明第二个额外字段的选项“小鼠”被勾选了）、`extra_field[2][大鼠]: "null"`（表明第二个额外字段的选项“大鼠”没有被勾选，可以省略）；
- 创建预约的最早提前天数应是一个正整数；
- 设备的内部编号`xx`会在创建或编辑预约信息时用到。

### 创建或编辑预约信息

在`./config`目录中，创建`config.yaml`，或者原位复制`./config/sample_config.yaml`文件并将副本重命名为`config.yaml`。

打开`config.yaml`文件，并填写或修改字段的值。样例和字段解释如下：
```yaml
# 填写用户信息配置文件的文件名（不含扩展名）（必填）
user: "xxxx"

# 填写目标仪器设备id，同时也是表单配置文件的文件名（不含扩展名）（必填）
equipment_id: "xx"

# 预约开始时间（格式：YYYY-MM-DD HH:MM:SS）（必填）
start: "2024-04-01 09:00:00"

# 预约结束时间（格式：YYYY-MM-DD HH:MM:SS）（必填）
end: "2024-04-01 09:30:00"

# 获取表单时临时使用的预约开始时间（格式：YYYY-MM-DD HH:MM:SS）
hackstart: ""

# 获取表单时临时使用的预约结束时间（格式：YYYY-MM-DD HH:MM:SS）
hackend: ""

# 添加或修改预约时使用的用户身份id，默认为空，即当前用户
hackuser_id: ""

# 填写已经存在的组件id将会修改此预约信息，默认为空，即创建新的预约
component_id: ""

# 是否卡点发送预约请求（true/false）
schedule: true

# 填写延迟发送预约请求的秒数，负数表示提前发送
delay_seconds: -2
```
额外说明：
- 必填参数：
  - 用户信息配置文件的文件名应与“创建或编辑用户信息”步骤的文件名一致，如用户信息配置文件位于`./config/users/alex.yaml`，则应填写`user: "alex"`；
  - 仪器表单配置文件的文件名应与“创建或编辑仪器表单”步骤的文件名一致，如仪器表单配置文件位于`./config/forms/123.yaml`，则应填写`equipment_id: "123"`；
  - 预约开始时间`start`和预约结束时间`end`应填写实际需要预约的时间段；
- 请谨慎使用以下功能，错误使用可能导致严重后果：
  - 临时使用的预约时段
    - 若预约开始时间和预约结束时间并不符合某些预约规则（如整点/半点开始、持续时间为30分钟的整数倍），可以寻找一个可以预约的、符合预约规则的时段（不一定是空闲的时间段），并分别填写`hackstart`和`hackend`（格式同`start`和`end`字段），以绕过部分规则正常生成表单；
    - 实际预约时只会尝试预约`start`到`end`之间的时段；
    - 如不填写`hackstart`和`hackend`（留空），则会以实际预约时间段提交表单，正常受到预约规则限制；
    - 此外，即使使用了`hackstart`和`hackend`字段，如果实际预约时段已经有人预约，或预约的时间段距今超出了仪器管理员规定的创建预约的最早提前天数，则仍然无法预约成功。
  - 用户身份
    - 若希望以他人身份创建或修改预约，请使用`hackuserid`并填写需要使用的用户身份id（比如仪器管理员）；
    - 若要获取目标用户身份id，请在大型仪器共享平台上找到该用户，并点击进入该用户主页，此时浏览器地址栏显示的网址类似以下链接：`https://dygx1.cpu.edu.cn/lims/!people/profile/index.xxx`，其中`xxx`（通常为数字）即为用户身份id；
    - 若不填写`hackuserid`（留空），则会正常以当前登录用户身份进行操作；
    - 在创建预约时，请确认目标用户有在当前仪器、当前时间段（`start`到`end`）预约的权限；
    - 在修改某预约时，请确认目标用户有对目标预约信息的操作权限（例如，以他人身份为其预约，或以仪器管理员身份修改当前仪器的*除预约人之外的*指定预约信息等）；
  - 组件ID
    - 若要修改某个预约信息而不是创建新的预约，请先找到该预约对应的组件ID，并填入`component_id`；
    - 预约组件ID可以从使用本程序预约后的返回消息得到，也可以在网页上通过打开开发者工具进行寻找；
    - 若不填写`component_id`(留空)，则会正常创建新的预约；
- 其它可选功能：
  - 卡点预约
    - 若将`schedule`设置为`true`（注意`true`应为小写），则程序会尽可能根据当前仪器可创建预约的最早提前天数、当前时间、目标预约时间和延迟发送预约请求的时间进行卡点发送预约请求，以期最快创建预约；
    - 若将`schedule`设置为`false`，则会立刻尝试发送预约请求；
    - 在尝试卡点预约时，本程序会先向服务器获取表单但不立即提交，因此在可以开始预约的时间点只需提交早已获得的表单即可，理论上比手动操作必须先获取表单（仅仅提前打开预约信息填写界面并不算获得了表单）再提交预约要快，前提是`delay_seconds`设置合理；
  - 卡点预约 -> 延迟设置
    - 尝试卡点发送预约请求时，由于服务器时间与运行本程序的设备时间可能有差异，以及网络可能有延迟，用户可以设置`delay_seconds`来进行微调；
    - 例如，假设本应在当前设备`09:00:00`发送预约信息：
      - 如果设置`delay_seconds: 2`，则会在当前设备`09:00:02`发送预约信息；
      - 如果设置`delay_seconds: -2`，则会在当前设备`08:59:58`发送预约信息。仅在`schedule`设置为`true`时有效。

### 提交预约
```shell
python ./main.py
```
