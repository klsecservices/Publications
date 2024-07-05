# Атакуем исследователей безопасности через Visual Studio
*Глеб Иванов*

Зачастую злоумышленники, чтобы скомпрометировать хост специалистов по ИБ, создают “вредоносные” PoC, которые, помимо заявленного функционала, имеют в себе [и скрытый](https://www.microsoft.com/en-us/security/blog/2021/01/28/zinc-attacks-against-security-researchers/). Чаще всего подобная техника направлена на эксплуатацию различных IDE-инструментов. Их можно разделить на несколько векторов:

- PreBuild/PostBuild Events
- Design-time target execution
- COM, Type Libraries

Более подробно об этих техниках можно почитать в [данной статье](https://www.outflank.nl/blog/2023/03/28/attacking-visual-studio-for-initial-access/).

Относительно недавно появилась ещё одна интересная техника по эксплуатации VS IDE. Направлена она в первую очередь на [SUO-файл](https://learn.microsoft.com/ru-ru/visualstudio/extensibility/internals/solution-user-options-dot-suo-file?view=vs-2022). Это файл параметров пользователя решения, который содержит в себе различные настройки/пресеты (положение и состояние окон, настройки отладки, настройки для проектов и т.д.). Сам файл создается автоматически при запуске или создании любого проекта и находится в скрытой папке проекта .vs по следующему пути:

```
...\.vs\[Project name]\v17\.suo
```

Чтобы понять, как все это работает, давайте посмотрим внутрь библиотеки Microsoft.VisualStudio.dll:

![Содержимое библиотеки](https://github.com/klsecservices/Publications/blob/03bd87493705375eff3678f8a73eb8feb9c37bc7/purpleshift/pics-vs/1-vs-load.png?raw=true)

![Содержимое библиотеки](https://github.com/klsecservices/Publications/blob/6c7a451f3e0fcc79a51d64c89b7e3e77172d4503/purpleshift/pics-vs/2-vs-load.png?raw=true)

Здесь мы видим, что для загрузки **VsToolboxService** (что находится непосредственно в suo-файле) используется функция **LoadOptions**, которая в свою очередь использует метод **BinaryFormatter.Deserialize**. Именно здесь и рождаются риски, связанные с десериализацией. Забавно, что сами представители Microsoft в [своем блоге](https://learn.microsoft.com/ru-ru/dotnet/standard/serialization/binaryformatter-security-guide) не рекомендуют использовать подобные методы обработки данных - однако сами же его и используют:

![Предупреждение](https://github.com/klsecservices/Publications/blob/03bd87493705375eff3678f8a73eb8feb9c37bc7/purpleshift/pics-vs/3-ms-warning.png?raw=true)
 
Всё это приводит к тому, что при запуске проекта VS (даже такого, в котором не содержится ни строчки кода), будет запускаться пейлоуд, что содержится в SUO-файле. Сам же файл будет перезаписываться новыми пресетами настроек пользователя, что может усложнять в дальнейшем расследование цепочки атаки, если не знать подобные сведения. PoC подобной техники можно найти [здесь](https://github.com/cjm00n/EvilSln). 

## Ловим малвару

Чтобы обнаружить и предотвратить такую атаку ещё до начала её действия, нужно рассмотреть этот пейлоуд в деталях. SUO имеет OLE-структуру, где наc интересует содержание элемента **VsToolboxService**:

![Содержание элемента VsToolboxService](https://github.com/klsecservices/Publications/blob/03bd87493705375eff3678f8a73eb8feb9c37bc7/purpleshift/pics-vs/3-vs-content.png?raw=true)

Внутри этого элемента мы как раз и можем обнаружить наш пейлоуд, закодированный в base64:

![Закодированный пейлоуд](https://github.com/klsecservices/Publications/blob/03bd87493705375eff3678f8a73eb8feb9c37bc7/purpleshift/pics-vs/4-vs-payload.png?raw=true)

Для детектирования такого подозрительного файла можно воспользоваться следующим YARA-правилом:


```
rule suo_deserialization 
{
    strings:
        $header = { D0 CF 11 E0 A1 B1 1A E1 } 
        $s = "VsToolboxService" wide
        $a1 = "AAEAAAD"
        $a2 = "ew0KICAgICckdHl"
        $a3 = "yAoFZNmAU3l"
        $a4 = "kscDYs0KCcYAAAP"
        $a5 = "PFByb3BlcnR5R3J"
        $a6 = "PD94bWwgdm" 
    condition:
       $header at 0 and $s and any of ($a*)
}
 
```

При применении данного правила на практике мы смогли обнаружить следующий интересный файл на VirusTotal:

![Подозрительный файл на VirusTotal](https://github.com/klsecservices/Publications/blob/03bd87493705375eff3678f8a73eb8feb9c37bc7/purpleshift/pics-vs/5-virustotal.png?raw=true)

С виду обычный файл. Однако, если посмотреть на то, что находится внутри, то мы обнаружим закодированный пейлоуд, который запускает powershell и качает ещё один файл с последующим его запуском:

![Код малвары](https://github.com/klsecservices/Publications/blob/03bd87493705375eff3678f8a73eb8feb9c37bc7/purpleshift/pics-vs/6-file-content.png?raw=true)

Данный файл является малварным и относится к семейству **Backdoor.MSIL.XWorm**. Запустив его в песочнице, можно увидеть его поведение - он закрепляется в системе через задачи в планировщике и выполняется каждую минуту:

![Схема работы малвары](https://github.com/klsecservices/Publications/blob/03bd87493705375eff3678f8a73eb8feb9c37bc7/purpleshift/pics-vs/7-backdoor-scheme.png?raw=true)

Кроме того, малвара общается с различными pastebin-сервисами в ожидании команд от атакующих ([T1102](https://attack.mitre.org/techniques/T1102/)):

![Обращение малвары к сервисам](https://github.com/klsecservices/Publications/blob/03bd87493705375eff3678f8a73eb8feb9c37bc7/purpleshift/pics-vs/8-backdoor-connection.png?raw=true)

Чтобы обезопасить себя от подобного рода атаки, рекомендуем воспользоваться нашим YARA-правилом, а также постоянно удалять “ненужные” файлы - такие, как SUO (их отсутствие никак не повредит вашему проекту). 

Помимо этого, стоит постоянно проводить код-ревью всего, что содержится в проекте, скачанном из недоверенных источников. А также, следуя указаниям в [блоге Microsoft](https://devblogs.microsoft.com/visualstudio/improving-developer-security-with-visual-studio-2022/), настроить “trusted location” для VS IDE.

