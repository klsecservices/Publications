# Old but gold: атака через GPP
*Глеб Иванов*

Существует довольно старая, но всё ещё работающая в некотором плане уязвимость, связанная с групповыми политиками Windows. В Active Directory есть такой механизм как Group Policy Preferences ([GPP](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn581922(v=ws.11))), который позволяет осуществлять множество сценариев по управлению локальными пользователями, сервисами, задачами и т.д. Нас больше всего здесь будет интересовать функционал добавления новых локальных пользователей на каждый хост в домене:

![Добавление нового пользователя через GPP](https://github.com/klsecservices/Publications/blob/master/purpleshift/pics-GPP/1new-user.png?raw=true)

С помощью этого инструмента администратор может спокойно создать нового локального пользователя, а также указать его пароль, который шифруется ключом AES-256. Политики GPP, как и все групповые политики, хранятся на SYSVOL в различных xml-файлах (Groups.xml, Services.xml, ScheduledTasks.xml и т.д.)

Всё шло хорошо до момента, пока Microsoft не выложила у себя в документации ключ, которым шифруются пароли локальных пользователей, добавленных с помощью GPP:

![Ключ шифрования для паролей](https://github.com/klsecservices/Publications/blob/master/purpleshift/pics-GPP/2ms-key.png?raw=true)

После этого началось множество инцидентов: атакующие искали спрятанные в xml-файлах пароли и расшифровывали их. Отсюда в матрице атак MITRE появилась подтехника [T1552.006](https://attack.mitre.org/techniques/T1552/006/). А компания Microsoft оперативно выпустила патч [MS14-025](https://support.microsoft.com/en-us/topic/ms14-025-vulnerability-in-group-policy-preferences-could-allow-elevation-of-privilege-may-13-2014-60734e15-af79-26ca-ea53-8cd617073c30), который запрещает ввод учётных данных в открытом виде:

![Запрет на создание нового пользователя через GPP](https://github.com/klsecservices/Publications/blob/master/purpleshift/pics-GPP/3warning.png?raw=true)

После выпуска патча эта атака потеряла популярность, и теперь встречается больше в различных CTF. Однако периодически атакующие ещё пытаются найти спрятанные пароли в файлах групповых политик. 

Чтобы поймать подобную активность, можно создать учётную запись, которая будет выступать в качестве ловушки (honeypot), подложив её данные в xml-файл. И если эта учётка когда-либо будет использоваться, это будет огромным триггером для проведения расследования:

![Содержимое xml-файла с cpassword](https://github.com/klsecservices/Publications/blob/master/purpleshift/pics-GPP/4honeypot.png?raw=true)

Для создания подобного xml-файла, имитирующего GPP и cpassword в нём, подойдёт скрипт [GPPDeception](https://github.com/RedSiege/GPPDeception). Также отличным инструментом для создания таких ловушек является [AD-Canaries](https://github.com/AirbusProtect/AD-Canaries), который рекомендуем взять на вооружение всем командам Blue Team.
