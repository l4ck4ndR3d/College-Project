1. clone the full repository
2. docker build -t cve-tracker .
3. docker run -d \
  --name cve-tracker \
  --env-file .env \
  -v /home/cyborg/Documents/Research_inter_1/cve_updates:/app/cve_updates \
  cve-tracker

`Dont forgot to upload in the .env`

4. Open Cron
   `crontab -e`
5. select any editor
6. Add this line
   ` */5 * * * * docker run --rm --env-file .env -v <Your_folder_Path>cve_updates:/app/cve_updates cve-tracker`
