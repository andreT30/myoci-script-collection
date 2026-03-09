# Recovering the `opc` SSH Key on OCI Linux 9

This guide explains how to recover SSH access to an Oracle Cloud
Infrastructure (OCI) Linux 9 instance by resetting the `opc` user's SSH
keys using the serial console and GRUB recovery.

## 1. Create a Serial Console Connection

Create a **serial console connection** to the instance from the OCI
Console or using Cloud Shell.

Documentation:
https://docs.oracle.com/en-us/iaas/Content/Compute/References/serialconsole.htm

Once created, connect to the instance through the serial console.

------------------------------------------------------------------------

## 2. Reboot the Instance

Reboot the machine from the OCI console or serial console.

While the system is rebooting, **continuously press `Esc`** until the
**GRUB menu** appears.

If a `grub>` prompt appears instead of the menu:

    exit

Then press **Enter** to return to the GRUB menu.

------------------------------------------------------------------------

## 3. Boot into Recovery Mode

1.  In the GRUB menu, select the **non‑UEK kernel**.
2.  Press **`e`** to edit the boot configuration.
3.  Find the line that begins with `linux`.
4.  At the **end of that line**, add:


```{=html}
    rd.break
```

5.  Press **Ctrl + X** to boot.

The system will boot into a **root shell**.

------------------------------------------------------------------------

## 4. Mount and Access the System

Run:

``` bash
chroot /sysroot
/usr/sbin/load_policy -i
exit
/bin/mount -o remount,rw /sysroot
```

------------------------------------------------------------------------

## 5. Replace the `opc` SSH Keys

Edit the authorized keys file:

``` bash
vi /sysroot/home/opc/.ssh/authorized_keys
```

Delete the old keys and paste the **correct SSH public key(s)**.

Save and exit.

------------------------------------------------------------------------

## 6. Reboot the Instance

    /usr/sbin/reboot -f

------------------------------------------------------------------------

## 7. Verify SSH Access

After the instance finishes rebooting:

    ssh opc@<instance-public-ip>

Confirm that the new SSH key allows successful login.
