from migrator import Migrator, User
import sys
if len(sys.argv) != 3:
    print("Usage: python cli.py <src_cred_path> <dst_cred_path>")
    exit(1)
src_cred_path = sys.argv[1]
dst_cred_path = sys.argv[2]

try:
    m = Migrator(src_cred_path, "hvrhs.org", dst_cred_path, "region1schools.org")
except FileNotFoundError as e:
    print("Cannot init Migrator: ", e)
    exit(1)

src_user = "jellington@hvrhs.org" #input("Enter source ({}) email: ".format(m.domains[0]))
dst_user = "jtech@region1schools.org" #input("Enter destination ({}) email: ".format(m.domains[1]))
u = m.create_user(src_user, dst_user)
if isinstance(u, User):
    print("User created successfully")
else:
    print("Error: ", u)
drives = u.get_owned_team_drives()
print("Available team drives: ")
for i, d in enumerate(drives):
    print("{}) {}".format(i+1, d))
sel = input("Enter number of drive(s) to migrate (space separated): ").split()
for s in sel:
    try:
        s = int(s) - 1
        if s < 0 or s >= len(drives):
            print("Invalid selection")
            continue
        targ = u.prepare_team_drive_for_migrate(drives[s])
        u.migrate_drive(drives[s], targ)
    except ValueError:
        print("Invalid selection")